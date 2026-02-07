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
	StravaID     string
	StravaSecret string
	AppURL       string
}

type StravaAuth struct {
	ExpiresAt    int64  `json:"expires_at"`
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

	query := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        strava_id TEXT UNIQUE,
        access_token TEXT,
        refresh_token TEXT,
        expires_at INTEGER,
        profile_img TEXT
    );`
	if _, err := db.Exec(query); err != nil {
		panic(err)
	}
	slog.Info("SQLite and Tables initialized")
}

func loadConfig() {
	_ = godotenv.Load()
	cfg = &Config{
		StravaID:     os.Getenv("STRAVA_CLIENT_ID"),
		StravaSecret: os.Getenv("STRAVA_CLIENT_SECRET"),
		AppURL:       os.Getenv("APP_URL"),
	}
}

// --- Database Logic ---

func saveUser(auth StravaAuth) error {
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
		err := db.QueryRow("SELECT strava_id, access_token, profile_img FROM users WHERE strava_id = ?",
			stravaID).Scan(&user.Athlete.ID, &user.AccessToken, &user.Athlete.ProfileImg)

		if err != nil {
			slog.Error("Context hydration failed", "error", err)
			http.Redirect(w, r, "/error", http.StatusFound)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- Handlers ---

func landing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Welcome to Annual Challenge</h1><a href='/login'>Login with Strava</a>")
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
	defer resp.Body.Close()

	var auth StravaAuth
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		http.Error(w, "Invalid response", http.StatusInternalServerError)
		return
	}

	if !auth.IsValid() {
		http.Redirect(w, r, "/error", http.StatusFound)
		return
	}

	if err := saveUser(auth); err != nil {
		slog.Error("Failed to save user", "error", err)
		return
	}

	sessionManager.Put(r.Context(), "user_id", auth.Athlete.ID)
	http.Redirect(w, r, "/user-dashboard", http.StatusFound)
}

func userDashboard(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(userContextKey).(StravaAuth)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Hello, %d</h1><img src='%s'><br><a href='/logout'>Logout</a>",
		user.Athlete.ID, user.Athlete.ProfileImg)
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
