package pkg

import "net/http"

// Proof-based API userinfo handler (stateless)
func proofApiUserInfoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userInfo, exists := getUserInfoFromContext(r.Context())
		if !exists {
			requireProofForAPI(w, r, "Cryptographic proof required to access user information.")
			return
		}

		// Get public key details
		pubKeyX, pubKeyY, err := getPublicKeyByUserID(userInfo.UserID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "failed to retrieve user keys",
			})
			return
		}

		pubHex := pubKeyX + ":" + pubKeyY

		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"stateless":     true,
			"user": map[string]any{
				"id":         userInfo.UserID,
				"username":   userInfo.Username,
				"login_type": userInfo.LoginType,
				"pubKeyX":    pubKeyX,
				"pubKeyY":    pubKeyY,
				"pubHex":     pubHex,
			},
			"message": "Successfully authenticated with cryptographic proof",
		})
	}
}

// Proof-based protected handler (stateless)
func proofProtectedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For GET requests, show the protected page but explain proof requirement
		if r.Method == "GET" {
			manager.renderTemplate(w, "protected.html", map[string]any{
				"RequiresProof": true,
				"Message":       "This is a stateless protected area. To access user data, make a POST request with a cryptographic proof.",
			})
			return
		}

		// For POST/API requests, user info should be in context from proof middleware
		userInfo, exists := getUserInfoFromContext(r.Context())
		if !exists {
			requireProofForAPI(w, r, "Cryptographic proof required to access this protected resource.")
			return
		}

		// Return user information as JSON for API requests
		if r.Header.Get("Accept") == "application/json" {
			writeJSON(w, http.StatusOK, map[string]any{
				"authenticated": true,
				"stateless":     true,
				"user": map[string]any{
					"id":         userInfo.UserID,
					"username":   userInfo.Username,
					"login_type": userInfo.LoginType,
				},
				"message": "Successfully authenticated with cryptographic proof",
			})
			return
		}

		// For web requests, render the protected page with user data
		manager.renderTemplate(w, "protected.html", map[string]any{
			"UserInfo":      userInfo,
			"Stateless":     true,
			"Authenticated": true,
		})
	})
}
