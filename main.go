package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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
	SyncedTo     int64  `json:"synced_to"`
	Athlete      struct {
		ID         int64  `json:"id"`
		ProfileImg string `json:"profile"`
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
	return s.AccessToken == "" || s.ExpiresAt == 0 || s.RefreshToken == ""
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
	db, err = sql.Open("sqlite", "strava_app.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		slog.Error("SQLite connection failed", "error", err)
		os.Exit(1)
	}
	db.SetMaxOpenConns(1)

	usersQuery := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        strava_id TEXT UNIQUE,
        access_token TEXT,
        refresh_token TEXT,
        expires_at INTEGER,
        profile_img TEXT,
        timezone TEXT,
        synced_to INTEGER
    );`
	if _, err := db.Exec(usersQuery); err != nil {
		panic(err)
	}

	// TODO: is there an activity ID? if so should store that too and use as primary key 

	// acitiviesQuery := `
	//    CREATE TABLE IF NOT EXISTS user_activities (
	//        id INTEGER PRIMARY KEY AUTOINCREMENT,
	//        strava_id TEXT UNIQUE FOREIGN_KEY,
	//        activity_type TEXT,
	//        _timestamp TIMESSTAMP,
	//        miles INTEGER,
	//        elevation_gain INTEGER
	//    );`
	// if _, err := db.Exec(acitiviesQuery); err != nil {
	// 	panic(err)
	// }

	slog.Info("SQLite and Tables initialized")
}

func loadConfig() {
	_ = godotenv.Load()
	cfg = &Config{
		StravaID:         os.Getenv("STRAVA_CLIENT_ID"),
		StravaSecret:     os.Getenv("STRAVA_CLIENT_SECRET"),
		StravaAPIVersion: os.Getenv("STRAVA_API_VERSION"),
		AppURL:           os.Getenv("APP_URL"),
	}
}

// --- Database Logic ---

func createUser(auth StravaAuth) error {
	query := `
    INSERT INTO users (strava_id, access_token, refresh_token, expires_at, profile_img) 
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(strava_id) DO UPDATE SET
        access_token = excluded.access_token,
        refresh_token = excluded.refresh_token,
        expires_at = excluded.expires_at,
        profile_img = excluded.profile_img;`
	_, err := db.Exec(query, auth.Athlete.ID, auth.AccessToken, auth.RefreshToken, auth.ExpiresAt, auth.Athlete.ProfileImg)
	return err
}

func bulkSaveActivities(activities []Activity) error {
	//TODO: creat bulk insert function
	query := ``
	_, err := db.Exec(query, )
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
	query := `
	UPDATE users 
    SET timezone = ?, 
    synced_to = ?, 
    WHERE strava_id = ?`
	_, err := db.Exec(query, user.Timezone, user.SyncedTo, user.Athlete.ID)
	return err
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
				refresh_token, 
				access_token, 
				profile_img, 
				timezone,
				synced_to 
			FROM users 
			WHERE strava_id = ?`,
			stravaID).Scan(
			&user.Athlete.ID,
			&user.RefreshToken,
			&user.AccessToken,
			&user.Athlete.ProfileImg,
			&user.Timezone,
			&user.SyncedTo)

		if err != nil {
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

	// TODO: make it so that it will check the exiration of key and then update the token
	if resp.StatusCode == http.StatusUnauthorized {
		err = refreshAccessToken(user)
		if err != nil {
			return nil, err
		}

		return makeStravaGetRequest(user, endpoint, params)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("strava API returned status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func getDetailedProfile(athleteID int) {

}

func CleanStravaTimezone(raw string) string {
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

func syncActivites(user StravaAuth) error {
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

	syncDate := user.SyncedTo
	if user.SyncedTo == 0 {
		janFirst := time.Date(time.Now().Year(), time.January, 1, 0, 0, 0, 0, loc)
		syncDate = janFirst.AddDate(0, 0, -1).Unix()
	}

	formattedSyncDate := strconv.FormatInt(syncDate, 10)
	params := url.Values{}
	params.Set("after", formattedSyncDate)

	data, err := makeStravaGetRequest(user, "https://www.strava.com/api/v3/activities", params)
	if err != nil {
		slog.Error("Error getting activities", "error", err)
		return err
	}

	var activities []Activity
	err = json.Unmarshal(data, &activities)
	if err != nil {
		return err
	}

	if len(activities) == 0 {
		return nil
	}

	// TODO: needs to flip through the pages if they exist and add to activity list
	// TODO: need to save all activities we'll make the queries fast and performant later.


	counts := make(map[string]int)
	for _, act := range activities {
		counts[act.Timezone]++
	}

	// TODO: get most common timezone
	mostCommonTimezone := "UTC"
	if user.Timezone == "" {
		user.Timezone = CleanStravaTimezone(mostCommonTimezone)
		slog.Info("clean timezone", "info", user.Timezone)
		slog.Info("dirty timezone", "info", mostCommonTimezone)
	}

	loc, err = time.LoadLocation(user.Timezone)
	if err != nil {
		slog.Error("User timezone failed to resolve", "error", err)
		loc = time.UTC
	}

	err = updateSyncMeta(user)
	if err != nil {
		return err
	}

	return nil
}

// --- Handlers ---

func landing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<a href='/login'>Login with Strava</a>")
}

func goLogin(w http.ResponseWriter, r *http.Request) {
	if sessionManager.Exists(r.Context(), "user_id") {
		http.Redirect(w, r, "/user-dashboard", http.StatusSeeOther)
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

	if err := createUser(auth); err != nil {
		slog.Error("Failed to save user", "error", err)
		http.Redirect(w, r, "/error", http.StatusFound)
		return
	}

	sessionManager.Put(r.Context(), "user_id", auth.Athlete.ID)
	http.Redirect(w, r, "/user-dashboard", http.StatusFound)
}

func userDashboard(w http.ResponseWriter, r *http.Request) {

	user, ok := r.Context().Value(userContextKey).(StravaAuth)
	if !ok {
		slog.Error("Context fetch failed")
		http.Error(w, "Internal Server Error", 500)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<div><h1>Hello, %d</h1><img src='%s'><br><a href='/logout'>Logout</a></div>\n",
		user.Athlete.ID, user.Athlete.ProfileImg)

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

// --- Main ---

func main() {
	f := initLogger()
	defer f.Close()

	loadConfig()
	initDB()
	defer db.Close()
	initValkey()

	mux := http.NewServeMux()
	mux.HandleFunc("/", landing)
	mux.HandleFunc("/login", goLogin)
	mux.HandleFunc("/logout", goLogout)
	mux.HandleFunc("/exchange_token", exchangeToken)
	mux.HandleFunc("/error", errorPage)

	// Protected
	mux.Handle("/user-dashboard", requireLogin(http.HandlerFunc(userDashboard)))

	slog.Info("Server starting on :8090")
	log.Fatal(http.ListenAndServe(":8090", sessionManager.LoadAndSave(mux)))
}
