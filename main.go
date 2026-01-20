package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

	var STRAVA_CLIENT_ID = os.Getenv("STRAVA_CLIENT_ID")
	var STRAVA_CLIENT_SECRET = os.Getenv("STRAVA_CLIENT_SECRET")

func goLogin(w http.ResponseWriter, req *http.Request) {
	APP_URL := os.Getenv("APP_URL")
	fmt.Println(STRAVA_CLIENT_ID)
	fmt.Println("id")
	redirectURL := fmt.Sprintf("%s/exchange_token", APP_URL)
	strava_oauth_url := fmt.Sprintf("http://www.strava.com/oauth/authorize?client_id=%s&response_type=code&redirect_uri=%s&approval_prompt=force&scope=read",
		STRAVA_CLIENT_ID,
		redirectURL)

	http.Redirect(w, req, strava_oauth_url, http.StatusFound)
}

func exchangeToken(w http.ResponseWriter, req *http.Request) {
	// TODO : save credentials. We'll need to place some sort of auth token on the user's machine
	// store the auth token and refresh tokens some how (valkey?)
	//
	fmt.Println(req)
	code := req.URL.Query().Get("code")

	staravaExchangeURL := fmt.Sprintf("http://www.strava.com/api/v3/oauth/token?client_id=%s&client_secret=%s&code=%s&grant_type=%s",
		STRAVA_CLIENT_ID,
		STRAVA_CLIENT_SECRET,
		code,
	)
	req, err := http.NewRequest("POST",
		staravaExchangeURL,
		nil)
	if err != nil {
		panic(err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println(body)

	APP_URL := os.Getenv("APP_URL")
	redirectURL := fmt.Sprintf("%s/user_dashboard", APP_URL)
	http.Redirect(w, req, redirectURL, http.StatusFound)
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
		STRAVA_CLIENT_ID,
		STRAVA_CLIENT_SECRET,
		refreshToken,
	)

	req, err := http.NewRequest("GET",
		stravaExchangeToken,
		nil,
	)

	if err != nil {
		return "", err
	}

	print(req)

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

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	fmt.Println("Status:", resp.Status)
	fmt.Println("Body:", string(body))
	return string(body), nil
}

func main() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	// if err != nil {
	// 	panic(err)
	// }


	http.HandleFunc("/login", goLogin)

	http.HandleFunc("/exchange_token", exchangeToken)

	http.HandleFunc("/user_dashboard", userDashboard)

	fmt.Println("Server listening on port 8090...")
	http.ListenAndServe(":8090", nil)

}
