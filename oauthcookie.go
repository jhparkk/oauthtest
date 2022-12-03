package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

func generateStateOAuthCookie(w http.ResponseWriter, cookieName string) string {
	expiration := time.Now().Add(1 * 24 * time.Hour)
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	cookie := &http.Cookie{
		Name:    cookieName,
		Value:   state,
		Expires: expiration,
	}
	http.SetCookie(w, cookie)

	return state
}
