package main

import (
	"net/http"
	"os"
	"io"
	"fmt"

	"github.com/joho/godotenv"
)

func goLogin(w http.ResponseWriter, req *http.Request) {
	fmt.Println("login")
}

func onLogin(w http.ResponseWriter, req *http.Request) {
	fmt.Println(req)
}


func stravaRefreshToken(refreshToken string) (string, error)  {
	accessToken := ""

	req, err := http.NewRequest(
		"GET",
		"https://www.strava.com/api/v3/athlete",
		nil,
	)
	if err != nil {
		return "", err
	}
	
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

	// Add Authorization header
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

	// STRAVA_CLIENT_ID := os.Getenv("CLIENT_ID")
	// STRAVA_CLIENT_SECRET := os.Getenv("STRAVA_CLIENT_SECRET")
	// STRAVA_ACCESS_TOKEN := os.Getenv("STRAVA_ACCESS_TOKEN")
	REFRESH_TOKEN := os.Getenv("REFRESH_TOKEN")

	STRAVA_ACCESS_TOKEN, err := stravaRefreshToken(REFRESH_TOKEN)
	if err != nil {
		panic(err)
	}



	stravaAPIFetch(STRAVA_ACCESS_TOKEN)

	http.HandleFunc("/login", goLogin)

	http.ListenAndServe(":8090", nil)

}
