package pkg

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Context keys for user info
type contextKey string

const userInfoContextKey contextKey = "userInfo"

// Helper functions for context
func setUserInfoContext(ctx context.Context, userInfo UserInfo) context.Context {
	return context.WithValue(ctx, userInfoContextKey, userInfo)
}

func getUserInfoFromContext(ctx context.Context) (UserInfo, bool) {
	userInfo, ok := ctx.Value(userInfoContextKey).(UserInfo)
	return userInfo, ok
}

// Proof-based authentication middleware for stateless access
func proofAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow GET requests to show the form
		if r.Method == "GET" {
			next.ServeHTTP(w, r)
			return
		}

		// For POST/API requests, require proof
		var reqData struct {
			Proof *schnorrProof `json:"proof"`
		}

		// Try to get proof from JSON body
		if r.Header.Get("Content-Type") == "application/json" {
			if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error": "invalid JSON or missing proof",
				})
				return
			}
		} else {
			// Try to get proof from form data
			if err := r.ParseForm(); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error": "failed to parse form",
				})
				return
			}

			proofData := r.FormValue("proof")
			if proofData != "" {
				var proof schnorrProof
				if err := json.Unmarshal([]byte(proofData), &proof); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]string{
						"error": "invalid proof format",
					})
					return
				}
				reqData.Proof = &proof
			}
		}

		if reqData.Proof == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "cryptographic proof required",
			})
			return
		}

		// Verify the proof
		if err := verifyProofWithReplay(reqData.Proof); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":   "invalid cryptographic proof",
				"details": err.Error(),
			})
			return
		}

		// Check if the public key is registered
		pubHex := reqData.Proof.PubKeyX + ":" + reqData.Proof.PubKeyY
		userInfo, exists := lookupUserByPubHex(pubHex)
		if !exists {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "unrecognized public key",
			})
			return
		}

		// Check if user has "simple" login type - they cannot use proof-based authentication
		if userInfo.LoginType == "simple" {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":   "access_denied",
				"message": "Your account is configured for simple login only. Proof-based authentication is not allowed.",
			})
			return
		}

		// CRITICAL SECURITY CHECK: Verify user hasn't logged out after proof timestamp
		initUserLogoutTracker()
		if userLogoutTracker.IsUserLoggedOut(userInfo.UserID, reqData.Proof.Ts) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":   "user_logged_out",
				"message": "User has been logged out. Please log in again to access protected resources.",
			})
			return
		}

		// Check if the user is logged out
		authTimestamp := reqData.Proof.Ts
		if userLogoutTracker.IsUserLoggedOut(userInfo.UserID, authTimestamp) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "user logged out",
			})
			return
		}

		// Add user info to request context for handlers to use
		r = r.WithContext(setUserInfoContext(r.Context(), userInfo))
		next.ServeHTTP(w, r)
	})
}

// Track user logout timestamps for proof-based auth security
type UserLogoutTracker struct {
	logoutTimes map[string]int64 // userID -> logout timestamp
	mu          sync.RWMutex
}

func NewUserLogoutTracker() *UserLogoutTracker {
	return &UserLogoutTracker{
		logoutTimes: make(map[string]int64),
	}
}

func (ult *UserLogoutTracker) SetUserLogout(userID string) {
	ult.mu.Lock()
	defer ult.mu.Unlock()
	ult.logoutTimes[userID] = time.Now().Unix()
}

func (ult *UserLogoutTracker) IsUserLoggedOut(userID string, authTimestamp int64) bool {
	ult.mu.RLock()
	defer ult.mu.RUnlock()

	logoutTime, exists := ult.logoutTimes[userID]
	if !exists {
		return false // User never logged out
	}

	// If auth timestamp is before logout time, user is logged out
	return authTimestamp < logoutTime
}

func (ult *UserLogoutTracker) ClearUserLogout(userID string) {
	ult.mu.Lock()
	defer ult.mu.Unlock()
	delete(ult.logoutTimes, userID)
}

// Helper function to create a stateless API response with proof requirement
func requireProofForAPI(w http.ResponseWriter, r *http.Request, message string) {
	if r.Header.Get("Accept") == "application/json" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":   "proof_required",
			"message": message,
			"instructions": map[string]string{
				"method":         "POST",
				"content_type":   "application/json",
				"body_format":    `{"proof": {"R": "...", "S": "...", "PubKeyX": "...", "PubKeyY": "...", "Nonce": "...", "Ts": ...}}`,
				"nonce_endpoint": "/nonce",
			},
		})
	} else {
		renderErrorPage(w, http.StatusUnauthorized, "Cryptographic Proof Required",
			message,
			"Use your key file to generate a cryptographic proof for this request.",
			"Stateless authentication requires proof", "/secured-login")
	}
}

// Global user logout tracker instance
var userLogoutTracker *UserLogoutTracker

// Initialize in main() or manager
func initUserLogoutTracker() {
	if userLogoutTracker == nil {
		userLogoutTracker = NewUserLogoutTracker()
	}
}
