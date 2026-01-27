package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"io"
	"log"
	"log/slog"
	_ "modernc.org/sqlite"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	StravaID     string
	StravaSecret string
	AppURL       string
}

type StravaAuth struct {
	ExpiresAt    int64 `json:"expires_at"`
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	Athlete      struct {
		ID         int64  `json:"id"`
		ProfileImg string `json:"profile"`
	} `json:"athlete"`
}

func (s *StravaAuth) IsValid() bool {
	return s.AccessToken != "" && s.Athlete.ID != 0
}

var cfg *Config
var db *sql.DB

func initDB() {
	// Using SQLite because it's simple and likely this app will have a total of
	// 1 user. I learned that because SQLite is just a file the you need to
	// use jounal_mode(WAL) which just makes it so you can read from the DB while
	// writing and then use the busy_timeout(5000) which effetively is a timeout
	// and retry
	var err error
	db, err = sql.Open("sqlite", "strava_app.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		slog.Error("Failed to connect to SQLite", "error", err)
		os.Exit(1)
	}
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		slog.Error("Database ping failed", "error", err)
		os.Exit(1)
	}

	slog.Info("SQLite initialized with WAL mode and Busy Timeout")
}

func initLogger() *os.File {
	logDir := "logs"
	logFile := "app.log"
	path := filepath.Join(logDir, logFile)

	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	multiWriter := io.MultiWriter(os.Stdout, file)

	logger := slog.New(slog.NewTextHandler(multiWriter, nil))
	slog.SetDefault(logger)

	return file
}

func LoadConfig() {
	err := godotenv.Load()
	if err != nil {
		slog.Error("Error loading .env file")
	}

	cfg = &Config{
		StravaID:     os.Getenv("STRAVA_CLIENT_ID"),
		StravaSecret: os.Getenv("STRAVA_CLIENT_SECRET"),
		AppURL:       os.Getenv("APP_URL"),
	}
}

func createTables() {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		strava_id TEXT UNIQUE,
		access_token TEXT,
		refresh_token TEXT,
		expires_at INTEGER,
		profile_img TEXT
	);`

	_, err := db.Exec(query)
	if err != nil {
		slog.Error("Failed to create tables", "error", err)
		panic(err)
	}
}

func saveUser(auth StravaAuth) error {
	query := `INSERT INTO users (strava_id, access_token, refresh_token, expires_at, profile_img) VALUES (?, ?, ?, ?, ?)`
	_, err := db.Exec(query, auth.Athlete.ID, auth.AccessToken,auth.RefreshToken, auth.ExpiresAt, auth.Athlete.ProfileImg)
	return err
}

func makeRequest(req *http.Request) (string, error) {
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func goLogin(w http.ResponseWriter, req *http.Request) {
	redirectURL := fmt.Sprintf("%s/exchange_token", cfg.AppURL)

	base, _ := url.Parse("https://www.strava.com/api/v3/oauth/authorize")
	params := url.Values{}
	params.Set("client_id", cfg.StravaID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURL)
	params.Set("approval_prompt", "force")
	params.Set("scope", "read")
	params.Add("scope", "read,activity:read_all")

	base.RawQuery = params.Encode()

	http.Redirect(w, req, base.String(), http.StatusFound)
}

func exchangeToken(w http.ResponseWriter, ogReq *http.Request) {
	// TODO : save credentials. We'll need to place some sort of auth token on the user's machine
	// store the auth token and refresh tokens some how (valkey?)
	//
	code := ogReq.URL.Query().Get("code")
	slog.Info("code=",code)
	endpoint := "https://www.strava.com/api/v3/oauth/token"

	data := url.Values{}
	data.Set("client_id", cfg.StravaID)
	data.Set("client_secret", cfg.StravaSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")

	stavaReq, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		slog.Error("Failed to create request", "error", err)
		return
	}

	stavaReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	body, err := makeRequest(stavaReq)
	if err != nil {
		slog.Error("Token exchange failed", "error", err)
		return
	}

	var auth StravaAuth
	if err := json.Unmarshal([]byte(body), &auth); err != nil {
		slog.Error("Failed to parse JSON", "error", err)
		http.Error(w, "Invalid response from Strava", http.StatusInternalServerError)
		return
	}

	if !auth.IsValid() {
		// TODO:create error message/page
		slog.Error("Athlete information is invalid", "error", auth.Athlete.ID)
		return
	}
	slog.Info("Athlete authenticated", "id", auth.Athlete.ID)
	slog.Info("Athlete schema", "athlete", auth)
	
	err = saveUser(auth)
	if err != nil {
		slog.Error("failed to save user", "Error", err)
		// TODO: send to error page also handle access denied case
		return
	}



	// APP_URL := os.Getenv("APP_URL")
	// redirectURL := fmt.Sprintf("%s/user_dashboard", APP_URL)
	// http.Redirect(w, req, redirectURL, http.StatusFound)
}

func userDashboard(w http.ResponseWriter, req *http.Request) {
	// TODO:
	// athleteData := stravaAPIFetch()
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Welcome to my Go Web Server!</h1>")
	fmt.Fprintf(w, "<p>This is an example of serving raw HTML.</p>")
}

func stravaRefreshToken(refreshToken string) (string, error) {
	// TODO: rewrite to check if token is expired and then run refresh
	// will need to check auth then pull user and if no user send to login
	accessToken := ""

	stravaExchangeToken := fmt.Sprintf("http://www.strava.com/api/v3/oauth/token?client_id=%s&client_secret=%s&grant_type=refresh_token&refresh_token=%s",
		cfg.StravaID,
		cfg.StravaSecret,
		refreshToken,
	)

	req, err := http.NewRequest("GET",
		stravaExchangeToken,
		nil,
	)

	body, err := makeRequest(req)
	if err != nil {
		slog.Error("request failed", "details", err)
	}
	if err != nil {
		return "", err
	}

	slog.Info("Exchange body", "exchange", body)

	return accessToken, nil
}

func stravaAPIFetch(accessToken string) (string, error) {

	req, err := http.NewRequest(
		"GET",
		"https://www.strava.com/api/v3/athlete",
		nil,
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	body, err := makeRequest(req)
	if err != nil {
		return "", err
	}

	fmt.Println("Body:", string(body))
	return string(body), nil
}

func main() {
	initLogger()
	LoadConfig()
	initDB()
	defer db.Close()
	createTables()

	http.HandleFunc("/login", goLogin)

	http.HandleFunc("/exchange_token", exchangeToken)

	http.HandleFunc("/user_dashboard", userDashboard)

	slog.Info("Server listening on port 8090...")
	http.ListenAndServe(":8090", nil)

}
