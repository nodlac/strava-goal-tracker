package main

import (
	"database/sql"
	"fmt"
	"github.com/joho/godotenv"
	"io"
	"log"
	"log/slog"
	_ "modernc.org/sqlite"
	"net/http"
	"os"
	"path/filepath"
)

type Config struct {
	StravaID     string
	StravaSecret string
	AppURL       string
}

var cfg *Config
var db *sql.DB

func initDB() {
	// Using SQLite because it's simple and likely this app will have a total of 
	// 1 user. I learned that because SQLite is just a file the you need to 
	// use jounal_mode(WAL) which just makes it so you can read from the DB while 
	// writing and then use the busy_timeout(5000) which effetively is a timeout 
	// and retry
    db, err := sql.Open("sqlite", "strava_app.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
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
		expires_at INTEGER
	);`

	_, err := db.Exec(query)
	if err != nil {
		slog.Error("Failed to create tables", "error", err)
		panic(err)
	}
}

func saveUser(stravaID string, token string) error {
    query := `INSERT INTO users (strava_id, access_token) VALUES (?, ?)`
    _, err := db.Exec(query, stravaID, token)
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
	strava_oauth_url := fmt.Sprintf("http://www.strava.com/oauth/authorize?client_id=%s&response_type=code&redirect_uri=%s&approval_prompt=force&scope=read",
		cfg.StravaID,
		redirectURL)

	http.Redirect(w, req, strava_oauth_url, http.StatusFound)
}

func exchangeToken(w http.ResponseWriter, req *http.Request) {
	// TODO : save credentials. We'll need to place some sort of auth token on the user's machine
	// store the auth token and refresh tokens some how (valkey?)
	//
	code := req.URL.Query().Get("code")

	staravaExchangeURL := fmt.Sprintf("http://www.strava.com/api/v3/oauth/token?client_id=%s&client_secret=%s&code=%s&grant_type=%s",
		cfg.StravaID,
		cfg.StravaSecret,
		code,
	)
	req, err := http.NewRequest("POST",
		staravaExchangeURL,
		nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(req)
	body, err := makeRequest(req)
	if err != nil {
		slog.Error("Strava API call failed", "details", err)
		http.Error(w, "Failed to contact Strava", http.StatusBadGateway)
	}

	fmt.Println(body)

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

	fmt.Println(string(body))

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

	http.HandleFunc("/login", goLogin)

	http.HandleFunc("/exchange_token", exchangeToken)

	http.HandleFunc("/user_dashboard", userDashboard)

	slog.Info("Server listening on port 8090...")
	http.ListenAndServe(":8090", nil)

}
