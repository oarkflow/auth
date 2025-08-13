package pkg

import (
	"context"
	"fmt"
	"net/http"
	"strings"

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
			// Check if this is an API request or browser request
			if isAPIRequest(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "authentication required",
				})
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}
		manager.CleanupExpiredTokens()

		if manager.IsTokenDenylisted(tokenStr) {
			// Check if this is an API request or browser request
			if isAPIRequest(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "session expired",
				})
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}
		decTok, err := token.DecryptToken(tokenStr, cfg.PasetoSecret)
		if err != nil {
			// Check if this is an API request or browser request
			if isAPIRequest(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "invalid session",
				})
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
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

// Helper function to determine if this is an API request
func isAPIRequest(r *http.Request) bool {
	// Check if the request path starts with /api/
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}

	// Check Accept header for JSON
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return true
	}

	// Check Content-Type header for JSON
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		return true
	}

	return false
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

// --- Rate limiting middleware
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)

		// Check if IP is rate limited
		if manager.Security.IsRateLimited(clientIP) {
			renderErrorPage(w, http.StatusTooManyRequests, "Too Many Requests",
				"You have exceeded the rate limit for requests.",
				"Please wait a moment before making another request.",
				fmt.Sprintf("Rate limit exceeded for IP: %s", clientIP), r.URL.Path)
			return
		}

		// Record this request
		manager.Security.RecordRequest(clientIP)

		next.ServeHTTP(w, r)
	})
}

// Phase 1: Login protection middleware
func loginProtectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			clientIP := getClientIP(r)
			identifier := clientIP // Can also use username if available

			// Check if login is blocked due to too many failed attempts
			if manager.Security.IsLoginBlocked(identifier) {
				renderErrorPage(w, http.StatusTooManyRequests, "Login Temporarily Blocked",
					"Too many failed login attempts.",
					fmt.Sprintf("Please wait %d minutes before trying again.", int(loginCooldownPeriod.Minutes())),
					fmt.Sprintf("Login blocked for identifier: %s", identifier), "/login")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
