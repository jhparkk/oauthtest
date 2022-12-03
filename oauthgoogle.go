package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/pat"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var googleOAuthConfig = oauth2.Config{
	RedirectURL:  "http://localhost:3000/auth/google/callback", // google api에서 설정한 승인된 리디렉션 URI와 같아야함
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_SECRET_KEY"),
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     google.Endpoint,
}

func googleLoginHandler(w http.ResponseWriter, r *http.Request) {
	state := generateStateOAuthCookie(w, "oauth_state_google")
	url := googleOAuthConfig.AuthCodeURL(state)
	log.Println("google oauth url : ", url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)

}

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v3/userinfo?access_token="

func getGoogleUserInfo(code string) ([]byte, error) {
	//get access token
	token, err := googleOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("Failed to exchange %s\n", err.Error())
	}
	res, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to get user info %s\n", err.Error())
	}

	return ioutil.ReadAll(res.Body)
}

func googleAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	oauthState, err := r.Cookie("oauth_state_google")
	if err != nil {
		log.Println("request cookie error : ", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	if r.FormValue("state") != oauthState.Value {
		log.Printf("invalid google oauth state cookie:%s  state:%s", oauthState.Value, r.FormValue("state"))
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	data, err := getGoogleUserInfo(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	fmt.Fprint(w, string(data))
}

func RegisterGoogleHandleFunc(mux *pat.Router) {
	mux.HandleFunc("/auth/google/login", googleLoginHandler)
	mux.HandleFunc("/auth/google/callback", googleAuthCallbackHandler) //승인된 리다이렉션 URI
}
