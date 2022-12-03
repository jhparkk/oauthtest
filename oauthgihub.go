package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/pat"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var githubOAuthConfig = oauth2.Config{
	RedirectURL:  "http://localhost:3000/auth/github/callback", // 승인된 리디렉션 URI와 같아야함
	ClientID:     "8188fe56139dc0e1b47a",
	ClientSecret: "09856fd5715e90da26d19719cd73c0d8df7822c0",
	//	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint: github.Endpoint,
}

func githubLoginHandler(w http.ResponseWriter, r *http.Request) {
	state := generateStateOAuthCookie(w, "oauth_state_github")
	url := githubOAuthConfig.AuthCodeURL(state)
	log.Println("github oauth url : ", url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

const oauthGithubUrlAPI = "https://api.github.com/user"

func getGithubUserInfo(code string) ([]byte, error) {
	//get access token
	token, err := githubOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("Failed to exchange %s\n", err.Error())
	}

	log.Println("token : ", token.AccessToken)

	//http.Header.Set("Authorization", "Bearer OAUTH-TOKEN")
	// res, err := http.Get(oauthGithubUrlAPI)
	req, err := http.NewRequest("GET", oauthGithubUrlAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to NewRequest %s\n", err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to Do %s\n", err.Error())
	}

	return ioutil.ReadAll(res.Body)
}

func githubAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	oauthState, err := r.Cookie("oauth_state_github")
	if err != nil {
		log.Println("request cookie error : ", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	if r.FormValue("state") != oauthState.Value {
		log.Printf("invalid github oauth state cookie:%s  state:%s", oauthState.Value, r.FormValue("state"))
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	data, err := getGithubUserInfo(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	fmt.Fprint(w, string(data))
}

func RegisterGithubHandleFunc(mux *pat.Router) {
	mux.HandleFunc("/auth/github/login", githubLoginHandler)
	mux.HandleFunc("/auth/github/callback", githubAuthCallbackHandler) //승인된 리다이렉션 URI
}
