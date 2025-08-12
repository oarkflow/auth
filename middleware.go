package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/oarkflow/paseto/token"
)

// --- Middleware ---
func pasetoMiddleware(cfg *Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := ""
		cookie, err := r.Cookie("session_token")
		if err == nil {
			tokenStr = cookie.Value
		} else if r.Header.Get("Authorization") != "" {
			auth := r.Header.Get("Authorization")
			if len(auth) > 7 && auth[:7] == "Bearer " {
				tokenStr = auth[7:]
			} else {
				tokenStr = auth
			}
		}
		if tokenStr == "" {
			renderErrorPage(w, http.StatusUnauthorized, "Authentication Required",
				"You must be logged in to access this page.",
				"Please log in to your account to continue.",
				"No authentication token found", "/login")
			return
		}
		manager.CleanupExpiredTokens()

		if manager.IsTokenDenylisted(tokenStr) {
			renderErrorPage(w, http.StatusUnauthorized, "Session Expired",
				"Your session has been terminated.",
				"Please log in again to access your account.",
				"Token found in logout denylist", "/login")
			return
		}
		decTok, err := token.DecryptToken(tokenStr, cfg.PasetoSecret)
		if err != nil {
			renderErrorPage(w, http.StatusUnauthorized, "Invalid Session",
				"Your authentication session is invalid or corrupted.",
				"Please log in again to continue.",
				fmt.Sprintf("Token decryption failed: %v", err), "/login")
			return
		}
		claims := decTok.Claims
		ctx := context.WithValue(r.Context(), "user", claims["sub"])

		// Add cache control headers to prevent browser caching of protected content
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- Utility Functions ---
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}
