package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alexedwards/scs/redisstore"
	"github.com/alexedwards/scs/v2"
	"github.com/gomodule/redigo/redis"
	"github.com/joho/godotenv"
	_ "modernc.org/sqlite"
)

// --- Types & Globals ---

const (
	KmToMeters    = 1000.0
	MetersToYards = 1.09361
	MetersToMiles = 0.000621371
	MetersToFeet  = 3.28084

	YardsToMeters = 0.9144
	MilesToMeters = 1609.34
	FeetToMeters  = 0.3048

	HrTosec = 3600
	SecToHr = 1 / 3600
)

type contextKey string

const userContextKey contextKey = "user"

var (
	cfg            *Config
	db             *sql.DB
	pool           *redis.Pool
	sessionManager *scs.SessionManager
)

type Config struct {
	StravaID         string
	StravaSecret     string
	StravaAPIVersion string
	AppURL           string
}

type StravaAuth struct {
	ExpiresAt    int64  `json:"expires_at"`
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	Timezone     string `json:"timezone"`
	Athlete      struct {
		ID              int64  `json:"id"`
		Username        string `json:"username"`
		ProfileImg      string `json:"profile"`
		MeasurementUnit string `json:"measurement_preference"`
	} `json:"athlete"`
}

func (s *StravaAuth) IsValid() bool {
	return s.AccessToken != "" && s.Athlete.ID != 0
}

func (s *StravaAuth) IsAccessTokenValid() bool {
	return s.ExpiresAt > (time.Now().Unix() + 60)
}

type StravaRefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

func (s *StravaRefreshResponse) IsValid() bool {
	return s.AccessToken != "" && s.ExpiresAt != 0 && s.RefreshToken != ""
}

type Sport struct {
	ID            int64          `json:"id"`
	Name          string         `json:"name"`
	StraveSportId string         `json:"strava_sport_id"`
	ImageUrl      sql.NullString `json:"image_url"`
	HasElevation  bool           `json:"has_elevation"`
}

type Goal struct {
	ID             int64           `json:"id"`
	SportId        int64           `json:"sport_id"`
	StartDate      time.Time       `json:"start_date"`
	EndDate        time.Time       `json:"end_date"`
	IncludeVirtual bool            `json:"include_virtual"`
	UserStravaId   int64           `json:"user_strava_id"`
	ElevationGoal  sql.NullFloat64 `json:"elevation_goal"`
	DistanceGoal   sql.NullFloat64 `json:"distance_goal"`
	DurationGoal   sql.NullFloat64 `json:"duration_goal"`
}

type GoalDisplay struct {
	StartDate      time.Time
	EndDate        time.Time
	IncludeVirtual bool
	SportName      string
	HasElevation   bool
	ElevationGoal  sql.NullFloat64
	DistanceGoal   sql.NullFloat64
	DurationGoal   sql.NullFloat64
}

type GoalForm struct {
	GoalID         int64     `form:"goal_id"`
	SportID        int64     `form:"sport_id"`
	IncludeVirtual bool      `form:"include_virtual"`
	StartDate      time.Time `json:"start_date"`
	EndDate        time.Time `json:"end_date"`
	Distance       float64   `form:"distance"`
	Elevation      float64   `form:"elevation"`
	Duration       int       `form:"duration"`
	Deleted        bool      `form:"deleted"`
}

type Activity struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Distance  float64   `json:"distance"`
	Elevation float64   `json:"total_elevation_gain"`
	Minutes   int       `json:"moving_time"`
	Type      string    `json:"type"`
	StartDate time.Time `json:"start_date"`
	Timezone  string    `json:"timezone"`
}

// Templates

var tmpl *template.Template

func init() {
	_ = godotenv.Load()
	tmpl = template.Must(template.ParseGlob("templates/*.html"))
}

func executeTemplate(w http.ResponseWriter, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html")
	err := tmpl.ExecuteTemplate(w, name, data)
	if err != nil {
		slog.Error("Template error", "template", name, "error", err)
		if os.Getenv("DEV") == "true" {
			http.Error(w, "Template error: "+err.Error(), 500)
		} else {
			http.Error(w, "Internal Server Error", 500)
		}
	}
}

// --- Initialization ---

func initLogger() *os.File {
	logDir := "logs"
	path := filepath.Join(logDir, "app.log")
	_ = os.MkdirAll(logDir, 0755)

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	multiWriter := io.MultiWriter(os.Stdout, file)
	slog.SetDefault(slog.New(slog.NewTextHandler(multiWriter, nil)))
	return file
}

func initValkey() {
	pool = &redis.Pool{
		MaxIdle: 10,
		Dial: func() (redis.Conn, error) {
			addr := os.Getenv("VALKEY_ADDR")
			if addr == "" {
				addr = "localhost:6379"
			}
			return redis.Dial("tcp", addr)
		},
	}
	sessionManager = scs.New()
	sessionManager.Store = redisstore.New(pool)
	sessionManager.Lifetime = 30 * 24 * time.Hour
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "goal_tracker.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		slog.Error("SQLite connection failed", "fatal", err)
		os.Exit(1)
	}
	db.SetMaxOpenConns(1)

	usersQuery := `
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			strava_id INTEGER UNIQUE,
			strava_username TEXT,
			access_token TEXT,
			refresh_token TEXT,
			expires_at INTEGER,
			profile_img TEXT,
			timezone TEXT,
			measurement_unit TEXT);`
	if _, err := db.Exec(usersQuery); err != nil {
		slog.Error("Failed to create users table", "fatal", err)
		panic(err)
	}

	sportsQuery := `
		CREATE TABLE IF NOT EXISTS sports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE,
			strava_sport_id TEXT,
			has_elevation BOOLEAN,
			image_URL TEXT
		);`
	if _, err := db.Exec(sportsQuery); err != nil {
		slog.Error("Failed to create sports table", "fatal", err)
		panic(err)
	}

	insertDefaultsQuery := `
				INSERT OR IGNORE INTO sports (name, strava_sport_id, has_elevation) VALUES 
				('Cycling', 'Ride', 1),
				('Running', 'Run', 1),
				('Swimming', 'Swim', 0);`
	_, err = db.Exec(insertDefaultsQuery)
	if err != nil {
		log.Fatalf("Failed to seed default sports: %v", err)
	}

	goalsQuery := `
		CREATE TABLE IF NOT EXISTS goals (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			start_date DATE,
			end_date DATE,
			include_virtual BOOLEAN,
			user_strava_id INTEGER,
			sport_id INTEGER,
			elevation_goal REAL,
			distance_goal REAL,
			duration_goal INTEGER,
			FOREIGN KEY(user_strava_id) REFERENCES users(strava_id)
			FOREIGN KEY(sport_id) REFERENCES sports(id)
			UNIQUE(start_date, end_date, user_strava_id, sport_id, include_virtual)
			);`
	if _, err := db.Exec(goalsQuery); err != nil {
		slog.Error("Failed to create goals table", "fatal", err)
		panic(err)
	}

	acitiviesQuery := `
		   CREATE TABLE IF NOT EXISTS user_activities (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				strava_activity_id INTEGER UNIQUE,
				user_strava_id INTEGER,
				activity_type TEXT,
				start_date INTEGER,
				distance REAL,
				elevation_gain REAL,
				duration INTEGER,
				FOREIGN KEY(user_strava_id) REFERENCES users(strava_id)
			);`
	if _, err := db.Exec(acitiviesQuery); err != nil {
		slog.Error("Failed to create user_activities table", "fatal", err)
		panic(err)
	}
}

func loadConfig() {
	cfg = &Config{
		StravaID:         os.Getenv("STRAVA_CLIENT_ID"),
		StravaSecret:     os.Getenv("STRAVA_CLIENT_SECRET"),
		StravaAPIVersion: os.Getenv("STRAVA_API_VERSION"),
		AppURL:           os.Getenv("APP_URL"),
	}
}

// --- Database Logic ---

func updateOrCreateUser(auth StravaAuth) (bool, error) {
	var exists bool
	// Check if user exists
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE strava_id = ?)", auth.Athlete.ID).Scan(&exists)
	if err != nil {
		return false, err
	}

	query := `
		INSERT INTO users (
			strava_id, 
			strava_username,
			access_token, 
			refresh_token, 
			expires_at, 
			profile_img, 
			measurement_unit
		) 
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(strava_id) DO UPDATE SET
			access_token = excluded.access_token,
			refresh_token = excluded.refresh_token,
			expires_at = excluded.expires_at,
			profile_img = excluded.profile_img,
			strava_username = excluded.strava_username;`
	_, err = db.Exec(
		query,
		auth.Athlete.ID,
		auth.Athlete.Username,
		auth.AccessToken,
		auth.RefreshToken,
		auth.ExpiresAt,
		auth.Athlete.ProfileImg,
		auth.Athlete.MeasurementUnit)
	if err != nil {
		return !exists, err
	}

	if !exists {
		if _, err := syncActivities(auth); err != nil {
			slog.Error("Failed to sync user activites on account create", "error", err)
			return !exists, err
		}
	}
	return !exists, nil
}

func bulkSaveActivities(db *sql.DB, activities []Activity, userStravaID int64) error {
	if len(activities) == 0 {
		return nil
	}

	numCols := 6
	placeholders := make([]string, 0, len(activities))
	args := make([]interface{}, 0, len(activities)*numCols)

	for _, act := range activities {
		placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?)")
		args = append(args,
			act.ID,
			userStravaID,
			act.Type,
			act.StartDate.Unix(),
			act.Distance,
			act.Elevation,
		)
	}
	query := fmt.Sprintf(`
			INSERT INTO user_activities (
				strava_activity_id, 
				user_strava_id, 
				activity_type, 
				start_date, 
				distance, 
				elevation_gain
			) VALUES %s
			ON CONFLICT(strava_activity_id) DO NOTHING;`,
		strings.Join(placeholders, ","))

	result, err := db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update user meta: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		slog.Warn("no user found to update", "strava_id", userStravaID)
	}
	slog.Info("Added user activities", "strave_id", userStravaID, "activity_count", len(activities))
	return err
}

func updateUserTokens(user StravaAuth, freshTokens StravaRefreshResponse) error {
	query := `
		UPDATE users 
		SET access_token = ?, 
			refresh_token = ?, 
			expires_at = ?
		WHERE strava_id = ?`
	_, err := db.Exec(query, freshTokens.AccessToken, freshTokens.RefreshToken, freshTokens.ExpiresAt, user.Athlete.ID)
	return err
}

func updateSyncMeta(user StravaAuth) error {
	slog.Info("updating user sync meta", "strava_id", user.Athlete.ID, "tz", user.Timezone)

	query := `
			UPDATE users 
			SET timezone = ?
			WHERE strava_id = ?`

	result, err := db.Exec(query, user.Timezone, user.Athlete.ID)
	if err != nil {
		return fmt.Errorf("failed to update user meta: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		slog.Warn("no user found to update", "strava_id", user.Athlete.ID)
	}

	return nil
}

func getUserActivityTotals(user StravaAuth) {
	// sqlite>  SELECT  sum(distance)/1609.3, sum(elevation_gain)*3.28084 from user_activities where activity_type like '%Ride';
	// 351.593115018952|23175.85376
	// sqlite>  SELECT  sum(distance)/1609.3, sum(elevation_gain)*3.28084 from user_activities where activity_type like '%Run';
	// 169.498850431865|23462.271092
	// sqlite>  SELECT  sum(distance)/1609.3, sum(elevation_gain)*3.28084 from user_activities where activity_type like '%Swim';
	// 5.65363822780091|0.0
}

func getUserActvitiesByMonth(user StravaAuth) {
	// sqlite>  SELECT  sum(distance)/1609.3, sum(elevation_gain)*3.28084 from user_activities where activity_type like '%Ride';
	// 351.593115018952|23175.85376
	// sqlite>  SELECT  sum(distance)/1609.3, sum(elevation_gain)*3.28084 from user_activities where activity_type like '%Run';
	// 169.498850431865|23462.271092
	// sqlite>  SELECT  sum(distance)/1609.3, sum(elevation_gain)*3.28084 from user_activities where activity_type like '%Swim';
	// 5.65363822780091|0.0
}

func fetchSports() ([]Sport, error) {
	var sports []Sport
	rows, err := db.Query(
		`SELECT 
				id,
				name,
				strava_sport_id,
				has_elevation,
				image_URL
			FROM sports`)
	if err != nil {
		slog.Error("Failed to Fetch Sports", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var s Sport
		err := rows.Scan(
			&s.ID,
			&s.Name,
			&s.StraveSportId,
			&s.HasElevation,
			&s.ImageUrl,
		)

		if err != nil {
			slog.Error("Failed to unmarshall Sport", "error", err)
			return nil, err
		}
		sports = append(sports, s)
	}

	return sports, nil
}

func fetchUserGoals(user StravaAuth) ([]Goal, error) {
	var goals []Goal
	rows, err := db.Query(
		`SELECT 
				id,
				start_date,
				end_date,
				include_virtual,
				user_strava_id,
				sport_id,
				elevation_goal,
				distance_goal,
				duration_goal
			FROM goals 
			WHERE user_strava_id = ?
				AND end_date > datetime('now')
			ORDER BY end_date DESC;`,
		user.Athlete.ID)
	if err != nil {
		slog.Error("Failed to Fetch Goals", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var g Goal
		err := rows.Scan(
			&g.ID,
			&g.StartDate,
			&g.EndDate,
			&g.IncludeVirtual,
			&g.UserStravaId,
			&g.SportId,
			&g.ElevationGoal,
			&g.DistanceGoal,
			&g.DurationGoal,
		)

		if err != nil {
			slog.Error("Failed to unmarshall Goal", "error", err)
			return nil, err
		}
		goals = append(goals, g)
	}

	return goals, nil
}

// --- Middleware ---

func requireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stravaID := sessionManager.GetInt64(r.Context(), "user_id")
		if stravaID == 0 {
			slog.Warn("Unauthorized access attempt")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		var user StravaAuth
		err := db.QueryRow(
			`SELECT 
					strava_id, 
					strava_username, 
					refresh_token, 
					access_token, 
					profile_img, 
					COALESCE(timezone, '') as timezone,
					measurement_unit
				FROM users 
				WHERE strava_id = ?`,
			stravaID).Scan(
			&user.Athlete.ID,
			&user.Athlete.Username,
			&user.RefreshToken,
			&user.AccessToken,
			&user.Athlete.ProfileImg,
			&user.Timezone,
			&user.Athlete.MeasurementUnit)
		if err != nil {
			sessionManager.Destroy(r.Context())
			http.Redirect(w, r, "/login", http.StatusFound)
			slog.Error("Context hydration failed", "error", err)
			http.Redirect(w, r, "/error", http.StatusFound)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- Starva requests ---

func refreshAccessToken(user StravaAuth) error {

	if user.RefreshToken == "" {
		return fmt.Errorf("User missing refresh token")
	}

	endpoint, err := url.Parse("https://www.strava.com/oauth/token")
	if err != nil {
		return fmt.Errorf("Error parsing refreshAccessToken endpoint")
	}

	params := url.Values{}
	params.Set("client_id", cfg.StravaID)
	params.Set("client_secret", cfg.StravaSecret)
	params.Set("refresh_token", user.RefreshToken)
	params.Set("grant_type", "refresh_token")

	resp, err := http.PostForm(endpoint.String(), params)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read the error message so we know why it failed
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("strava error %d: %s", resp.StatusCode, string(body))
	}
	var freshTokens StravaRefreshResponse

	if err := json.NewDecoder(resp.Body).Decode(&freshTokens); err != nil {
		return fmt.Errorf("Failed to decodde response")
	}

	if !freshTokens.IsValid() {
		return fmt.Errorf("Refresh Token Data Invalid")
	}

	err = updateUserTokens(user, freshTokens)
	return err

}

func makeStravaGetRequest(
	user StravaAuth,
	endpoint string,
	params url.Values) ([]byte, error) {

	encodedURL, err := url.Parse(endpoint)
	if err != nil {
		slog.Error("Error parsing url", "error", err)
		return nil, err
	}

	if !user.IsAccessTokenValid() {
		err = refreshAccessToken(user)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest("GET", encodedURL.String(), nil)
	if err != nil {
		slog.Error("Failed to create http request", "error", err)
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", user.AccessToken))

	if params != nil {
		req.URL.RawQuery = params.Encode()
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Failed to make request to Strava", "error", err)
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("Sorry. Strava has recieved too many requests from our app try syncing again later")
	}

	if resp.StatusCode == http.StatusUnauthorized {
		if err = refreshAccessToken(user); err != nil {
			return nil, err
		}

		return makeStravaGetRequest(user, endpoint, params)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("strava API returned status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func cleanStravaTimezone(raw string) string {
	// Strava format: "(GMT-08:00) America/Los_Angeles"
	parts := strings.SplitN(raw, " ", 2)
	if len(parts) < 2 {
		return "UTC" // Fallback if string is malformed or empty
	}

	cleanTZ := parts[1]

	// Verify it's a valid IANA timezone before saving
	_, err := time.LoadLocation(cleanTZ)
	if err != nil {
		return "UTC"
	}

	return cleanTZ
}

func syncActivities(user StravaAuth) ([]Activity, error) {

	var err error

	timezone := user.Timezone
	if timezone == "" {
		timezone = "UTC"
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		slog.Warn("Invalid timezone, defaulting to UTC", "error", err)
		loc = time.UTC
	}

	var syncUnix sql.NullInt64
	err = db.QueryRow(
		`SELECT 
				MAX(start_date)
			FROM user_activities 
			WHERE user_strava_id = ?`,
		user.Athlete.ID).Scan(
		&syncUnix)

	var syncDate int64
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("database error: %w", err)
	}
	if syncUnix.Valid && syncUnix.Int64 > 0 {
		// We found a previous sync!
		syncDate = syncUnix.Int64
	} else {
		// New User: Default to the beginning of the current year
		// We calculate the Unix timestamp for Jan 1st
		syncDate = time.Date(time.Now().Year(), time.January, 1, 0, 0, 0, 0, loc).AddDate(0, 0, -1).Unix()
	}

	var activities []Activity
	formattedSyncDate := strconv.FormatInt(syncDate, 10)
	activitiesPerPage := 200
	page := 1
	params := url.Values{}
	params.Set("after", formattedSyncDate)
	params.Set("per_page", strconv.Itoa(activitiesPerPage))

	for {
		params.Set("page", strconv.Itoa(page))

		var currentBatch []Activity
		data, err := makeStravaGetRequest(user, "https://www.strava.com/api/v3/activities", params)
		if err != nil {
			slog.Error("Error getting activities", "error", err)
			return nil, err
		}

		err = json.Unmarshal(data, &currentBatch)
		if err != nil {
			return nil, err
		}

		activities = append(activities, currentBatch...)

		if len(currentBatch) < activitiesPerPage {
			break

		}
		page++
		time.Sleep(100 * time.Millisecond)
	}

	counts := make(map[string]int)
	for _, act := range activities {
		counts[act.Timezone]++
	}

	if user.Timezone == "" {

		var mostCommonTimezone string
		maxCounts := 0

		for tz, count := range counts {
			if count > maxCounts {
				maxCounts = count
				mostCommonTimezone = tz
			}
		}

		if mostCommonTimezone == "" {
			mostCommonTimezone = "UTC"
		}

		user.Timezone = cleanStravaTimezone(mostCommonTimezone)
	}

	loc, err = time.LoadLocation(user.Timezone)
	if err != nil {
		slog.Error("User timezone failed to resolve", "error", err)
		loc = time.UTC
	}

	err = bulkSaveActivities(db, activities, user.Athlete.ID)
	if err != nil {
		return nil, err
	}

	err = updateSyncMeta(user)
	if err != nil {
		return nil, err
	}

	return activities, nil
}

// --- Handlers ---

func landing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<a href='/login'>Login with Strava</a>")
}

func goLogin(w http.ResponseWriter, r *http.Request) {
	if sessionManager.Exists(r.Context(), "user_id") {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	redirectURL := fmt.Sprintf("%s/exchange_token", cfg.AppURL)
	base, _ := url.Parse("https://www.strava.com/api/v3/oauth/authorize")
	params := url.Values{}
	params.Set("client_id", cfg.StravaID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURL)
	params.Set("approval_prompt", "force")
	params.Set("scope", "read,activity:read_all")

	base.RawQuery = params.Encode()
	http.Redirect(w, r, base.String(), http.StatusFound)
}

func exchangeToken(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	data := url.Values{
		"client_id":     {cfg.StravaID},
		"client_secret": {cfg.StravaSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
	}

	resp, err := http.PostForm("https://www.strava.com/api/v3/oauth/token", data)
	if err != nil {
		slog.Error("Token exchange request failed", "error", err)
		http.Redirect(w, r, "/error", http.StatusFound)
		return
	}
	defer resp.Body.Close()

	var auth StravaAuth
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		slog.Error("Error reading athlete auth", "error", err)
		http.Error(w, "Invalid response", http.StatusInternalServerError)
		return
	}

	if !auth.IsValid() {
		slog.Error("Invalid athlete auth")
		http.Redirect(w, r, "/error", http.StatusFound)
		return
	}

	if auth.Athlete.MeasurementUnit == "" {
		auth.Athlete.MeasurementUnit = "feet"
	}

	isNew, err := updateOrCreateUser(auth)
	if err != nil {
		slog.Error("Failed to save user", "error", err)
		http.Redirect(w, r, "/error", http.StatusFound)
		return
	}

	sessionManager.Put(r.Context(), "user_id", auth.Athlete.ID)

	if isNew {
		http.Redirect(w, r, "/goals", http.StatusFound)
	}

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func handleSetGoals(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(userContextKey).(StravaAuth)
	if !ok {
		slog.Error("Context fetch failed")
		http.Error(w, "Internal Server Error", 500)
		return
	}

	goals, err := fetchUserGoals(user)
	if err != nil {
		slog.Error("Error getting goals", "error", err)
	}

	sports, err := fetchSports()
	if err != nil {
		slog.Error("Error getting sports", "error", err)
	}

	executeTemplate(w, "set-goals.html", map[string]interface{}{
		"ProfileImg":      user.Athlete.ProfileImg,
		"MeasurementUnit": user.Athlete.MeasurementUnit,
		"Goals":           goals,
		"Sports":          sports,
	})
}

func handleUserDashboard(w http.ResponseWriter, r *http.Request) {

	user, ok := r.Context().Value(userContextKey).(StravaAuth)
	if !ok {
		slog.Error("Context fetch failed")
		http.Error(w, "Internal Server Error", 500)
		return
	}

	measurementLabel := "Metric"
	if user.Athlete.MeasurementUnit == "feet" {
		measurementLabel = "Imperial"
	}

	executeTemplate(w, "user-dashbaord.html", map[string]interface{}{
		"Username":         user.Athlete.Username,
		"ProfileImg":       user.Athlete.ProfileImg,
		"MeasurementLabel": measurementLabel,
		"Timezone":         user.Timezone,
	})

	err := refreshAccessToken(user)
	if err != nil {
		slog.Error("error refreshing token", "error", err)
	}

	// // test activiteis endpoint and token refresh
	// activities, err := getActivites(user)
	// if err != nil {
	// 	slog.Error("Error fetching activites", "error", err)
	// }
	// // 2. Turn the slice into "Pretty" JSON bytes
	// prettyJSON, err := json.MarshalIndent(activities, "", "    ")
	// if err != nil {
	// 	slog.Error("JSON marshaling failed", "error", err)
	// 	return
	// }

	// 3. Set content type and print to webpage
	// fmt.Fprintf(w, "<html><body><h1>Activities</h1><pre>%s</pre></body></html>", string(prettyJSON))
}

func goLogout(w http.ResponseWriter, r *http.Request) {
	sessionManager.Destroy(r.Context())
	http.Redirect(w, r, "/", http.StatusFound)
}

func errorPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Uh Oh</h1><p>An error has occurred.</p><a href='/'>Home</a>")
}

// --- HTMX Handlers ---

func handleSaveGoals(w http.ResponseWriter, r *http.Request) {

	logAndFail := func(err error) {
		slog.Error("Couldn't convert goal param", "error", err)
		fmt.Fprintf(w, `
					<div>
						<button hx-post="/" hx-target="#sync-ui" hx-indicator="#loading">Save</button>
						<p>Failed to save!</p>
					</div>
				`)
		http.Error(w, "Failed to save form", 400)
	}

	user, ok := r.Context().Value(userContextKey).(StravaAuth)
	if !ok {
		slog.Error("Context fetch failed")
		http.Error(w, "Internal Server Error", 500)
		return
	}

	err := r.ParseForm()
	if err != nil {
		slog.Error("Failed to parse form data", "error", err)
		http.Error(w, "Error parsing form data", 500)
	}

	for i := 0; i < 100; i++ {
		sportIDStr := r.Form.Get(fmt.Sprintf("goals[%d].sport_id", i))
		if sportIDStr == "" {
			break
		}

		sportID, _ := strconv.ParseInt(sportIDStr, 10, 64)
		goalIDStr := r.Form.Get(fmt.Sprintf("goals[%d].goal_id", i))
		goalID, _ := strconv.ParseInt(goalIDStr, 10, 64)
		includeVirtual, _ := strconv.ParseBool("goals[%d].include_virtual")
		startDateStr := r.Form.Get(fmt.Sprintf("goals[%d].start_date", i))
		startDate := time.Date(time.Now().Year(), 1, 1, 0, 0, 0, 0, time.UTC)
		if startDateStr != "" {
			startDate, err = time.Parse("2006-01-02", startDateStr)
			if err != nil {
				logAndFail(err)
				return
			}
		}
		endDateStr := r.Form.Get(fmt.Sprintf("goals[%d].end_date", i))
		endDate, err := time.Parse("2006-01-02", endDateStr)
		if err != nil {
			logAndFail(err)
			return
		}
		distanceStr := r.Form.Get(fmt.Sprintf("goals[%d].distance", i))
		distance, err := strconv.ParseFloat(distanceStr, 64)
		if err != nil {
			logAndFail(err)
			return
		}
		elevationStr := r.Form.Get(fmt.Sprintf("goals[%d].elevation", i))
		elevation, _ := strconv.ParseFloat(elevationStr, 64)
		durationStr := r.Form.Get(fmt.Sprintf("goals[%d].duration", i))
		duration, err := strconv.Atoi(durationStr)
		if err != nil {
			logAndFail(err)
			return
		}
		deletedStr := r.Form.Get(fmt.Sprintf("goals[%d].deleted", i))
		deleted, err := strconv.ParseBool(deletedStr)
		if err != nil {
			logAndFail(err)
			return
		}

		formattedGoal := GoalForm{
			GoalID:         goalID,
			SportID:        sportID,
			IncludeVirtual: includeVirtual,
			StartDate:      startDate,
			EndDate:        endDate,
			Distance:       distance * KmToMeters,
			Elevation:      elevation,
			Duration:       duration * HrTosec,
			Deleted:        deleted,
		}
		if user.Athlete.MeasurementUnit == "feet" {
			formattedGoal.Distance = formattedGoal.Distance * MilesToMeters
			formattedGoal.Elevation = formattedGoal.Elevation * FeetToMeters
		}

		var query string
		var args []interface{}
		if goalID == 0 {
			query = `
				INSERT INTO goals (
					user_strava_id,
					start_date,
					end_date,
					include_virtual,
					sport_id,
					elevation_goal,
					distance_goal,
					duration_goal
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

			args = []interface{}{
				user.Athlete.ID,
				formattedGoal.StartDate,
				formattedGoal.EndDate,
				formattedGoal.IncludeVirtual,
				formattedGoal.SportID,
				formattedGoal.Elevation,
				formattedGoal.Distance,
				formattedGoal.Duration,
			}

		} else if deleted == true {
			query = `
				DELETE FROM  goals 
				WHERE id = ?
					AND user_strava_id = ?`
			args = []interface{}{
				formattedGoal.GoalID,
				user.Athlete.ID,
			}
		} else {
			query = `
				UPDATE goals 
				SET 
					start_date = ?,
					end_date = ?,
					include_virtual = ?,
					sport_id = ?,
					elevation_goal = ?,
					distance_goal = ?,
					duration_goal = ?
				WHERE id = ?
					AND user_strava_id = ?`

			args = []interface{}{
				formattedGoal.StartDate,
				formattedGoal.EndDate,
				formattedGoal.IncludeVirtual,
				formattedGoal.SportID,
				formattedGoal.Elevation,
				formattedGoal.Distance,
				formattedGoal.Duration,
				formattedGoal.GoalID,
				user.Athlete.ID,
			}
		}

		_, err = db.Exec(query, args...)

		if err != nil {
			slog.Error("Failed to save goals", "error", err)
			fmt.Fprintf(w, `
				<div>
					<button hx-post="/" hx-target="#sync-ui" hx-indicator="#loading">Save</button>
					<p>Failed to save!</p>
				</div>
			`)
			http.Error(w, "Internal Server Error", 500)
			return
		}

	}
	fmt.Fprintf(w, `
		<div>
			<button hx-post="/" hx-target="#sync-ui" hx-indicator="#loading">Save</button>
			<p>Success!</p>
		</div>
	`)
}

func handleSyncActivities(w http.ResponseWriter, r *http.Request) {

	user, ok := r.Context().Value(userContextKey).(StravaAuth)
	if !ok {
		slog.Error("Context fetch failed")
		http.Error(w, "Internal Server Error", 500)
		return
	}

	activites, err := syncActivities(user)
	if err != nil {
		fmt.Fprintf(w, `
    <div>
        <button hx-post="/sync" hx-target="#sync-ui" hx-indicator="#loading">Sync Again</button>
        <p>Failed! -- %s</p>
    </div>
	`, err)
		return
	}

	fmt.Fprintf(w, `
    <div>
        <button hx-post="/sync" hx-target="#sync-ui" hx-indicator="#loading">Sync Again</button>
        <p>Success! Syned %d activites at: <b>%s</b></p>
    </div>
`, len(activites), time.Now().Format("2006-01-02 15:04:05"))
}

// --- Main ---

func main() {
	loadConfig()
	f := initLogger()
	defer f.Close()

	initDB()
	defer db.Close()
	initValkey()

	mux := http.NewServeMux()
	mux.HandleFunc("/", landing)
	mux.HandleFunc("/login", goLogin)
	mux.HandleFunc("/logout", goLogout)
	mux.HandleFunc("/exchange_token", exchangeToken)
	mux.HandleFunc("/error", errorPage)

	// Static files
	mux.Handle("/styles.css", http.FileServer(http.Dir("templates")))

	// Protected
	mux.Handle("/dashboard", requireLogin(http.HandlerFunc(handleUserDashboard)))
	mux.Handle("/goals", requireLogin(http.HandlerFunc(handleSetGoals)))
	mux.Handle("/save-goals", requireLogin(http.HandlerFunc(handleSaveGoals)))
	mux.Handle("/sync", requireLogin(http.HandlerFunc(handleSyncActivities)))

	slog.Info("Server starting on :8080 use :8090 proxy")
	log.Fatal(http.ListenAndServe(":8080", sessionManager.LoadAndSave(mux)))
}
