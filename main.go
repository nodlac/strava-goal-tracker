package main

import (
	"net/http"
	"os"
	"io"
	"fmt"

	"github.com/joho/godotenv"
)

func stravaAPIFetch(accessToken string) {
	
	req, err := http.NewRequest(
		"GET",
		"https://www.strava.com/api/v3/athlete",
		nil,
	)
	if err != nil {
		panic(err)
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
		panic(err)
	}

	fmt.Println("Status:", resp.Status)
	fmt.Println("Body:", string(body))
}

func main() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	// STRAVA_CLIENT_ID := os.Getenv("CLIENT_ID")
	// STRAVA_CLIENT_SECRET := os.Getenv("STRAVA_CLIENT_SECRET")
	STRAVA_ACCESS_TOKEN := os.Getenv("STRAVA_ACCESS_TOKEN")
	// REFRESH_TOKEN := os.Getenv("REFRESH_TOKEN")

	stravaAPIFetch(STRAVA_ACCESS_TOKEN)

}
