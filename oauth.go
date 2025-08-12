package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oarkflow/paseto/token"
)

// OAuth 2.0 Authorization Code Flow handlers
func oauthAuthorizeHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse authorization request parameters
		clientID := r.URL.Query().Get("client_id")
		redirectURI := r.URL.Query().Get("redirect_uri")
		responseType := r.URL.Query().Get("response_type")
		scope := r.URL.Query().Get("scope")
		state := r.URL.Query().Get("state")

		if clientID == "" || redirectURI == "" || responseType != "code" {
			renderErrorPage(w, http.StatusBadRequest, "Invalid Request",
				"Required parameters are missing or invalid.",
				"Please check your OAuth client configuration.",
				"Missing client_id, redirect_uri, or invalid response_type", "")
			return
		}

		// Validate client
		client, err := manager.Vault.GetClient(clientID)
		if err != nil || !client.IsApproved {
			renderErrorPage(w, http.StatusBadRequest, "Invalid Client",
				"The client application is not authorized.",
				"Please contact the application provider.",
				"Client not found or not approved", "")
			return
		}

		// Validate redirect URI
		validRedirect := false
		for _, uri := range client.RedirectURIs {
			if uri == redirectURI {
				validRedirect = true
				break
			}
		}
		if !validRedirect {
			renderErrorPage(w, http.StatusBadRequest, "Invalid Redirect URI",
				"The redirect URI is not registered for this client.",
				"Please contact the application provider.",
				"Redirect URI not in client's registered URIs", "")
			return
		}

		// Check if user is authenticated
		tokenStr := ""
		cookie, err := r.Cookie("paseto")
		if err == nil {
			tokenStr = cookie.Value
		}

		if tokenStr == "" {
			// Redirect to login with OAuth context
			loginURL := fmt.Sprintf("/login?client_id=%s&redirect_uri=%s&scope=%s&state=%s",
				url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(scope), url.QueryEscape(state))
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		// Validate token
		decTok, err := token.DecryptToken(tokenStr, cfg.PasetoSecret)
		if err != nil {
			loginURL := fmt.Sprintf("/login?client_id=%s&redirect_uri=%s&scope=%s&state=%s",
				url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(scope), url.QueryEscape(state))
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		userID, ok := decTok.Claims["sub"].(string)
		if !ok {
			renderErrorPage(w, http.StatusInternalServerError, "Authentication Error",
				"Unable to identify user from token.",
				"Please try logging in again.",
				"Invalid token claims", "/login")
			return
		}

		// Show consent page
		scopes := strings.Split(scope, " ")
		if scope == "" {
			scopes = client.Scopes
		}

		manager.renderTemplate(w, "consent.html", map[string]any{
			"Client":      client,
			"Scopes":      scopes,
			"RedirectURI": redirectURI,
			"State":       state,
			"UserID":      userID,
		})
	}
}

func oauthConsentHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse form data
		clientID := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		state := r.FormValue("state")
		userID := r.FormValue("user_id")
		action := r.FormValue("action")

		if action == "deny" {
			// Redirect with error
			errorURL := fmt.Sprintf("%s?error=access_denied&state=%s", redirectURI, state)
			http.Redirect(w, r, errorURL, http.StatusFound)
			return
		}

		// Get approved scopes
		approvedScopes := r.Form["scopes"]
		if len(approvedScopes) == 0 {
			errorURL := fmt.Sprintf("%s?error=access_denied&state=%s", redirectURI, state)
			http.Redirect(w, r, errorURL, http.StatusFound)
			return
		}

		// Generate authorization code
		code := generateRandomString(32)
		authCode := &AuthorizationCode{
			Code:        code,
			ClientID:    clientID,
			UserID:      userID,
			RedirectURI: redirectURI,
			Scopes:      approvedScopes,
			ExpiresAt:   time.Now().Add(10 * time.Minute),
		}

		err := manager.Vault.CreateAuthorizationCode(authCode)
		if err != nil {
			renderErrorPage(w, http.StatusInternalServerError, "Server Error",
				"Unable to process authorization.",
				"Please try again later.",
				fmt.Sprintf("Failed to create authorization code: %v", err), "")
			return
		}

		// Redirect with authorization code
		successURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, code, state)
		http.Redirect(w, r, successURL, http.StatusFound)
	}
}

func oauthTokenHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "invalid_request"})
			return
		}

		grantType := r.FormValue("grant_type")

		switch grantType {
		case "authorization_code":
			handleAuthorizationCodeGrant(w, r, cfg)
		case "refresh_token":
			handleRefreshTokenGrant(w, r, cfg)
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "unsupported_grant_type",
				"error_description": "Grant type not supported",
			})
		}
	}
}

func handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, cfg *Config) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")

	// Validate client
	client, err := manager.Vault.GetClient(clientID)
	if err != nil || client.ClientSecret != clientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_client",
			"error_description": "Client authentication failed",
		})
		return
	}

	// Validate authorization code
	authCode, err := manager.Vault.GetAuthorizationCode(code)
	if err != nil || authCode.Used || authCode.ExpiresAt.Before(time.Now()) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "Authorization code is invalid or expired",
		})
		return
	}

	if authCode.ClientID != clientID || authCode.RedirectURI != redirectURI {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "Authorization code was not issued to this client",
		})
		return
	}

	// Mark code as used
	manager.Vault.UseAuthorizationCode(code)

	// Generate access token
	accessToken := generateRandomString(32)
	refreshToken := generateRandomString(32)

	// Store tokens
	accessTokenRecord := &AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    authCode.UserID,
		Scopes:    authCode.Scopes,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	refreshTokenRecord := &RefreshToken{
		Token:     refreshToken,
		ClientID:  clientID,
		UserID:    authCode.UserID,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days
	}

	err = manager.Vault.CreateAccessToken(accessTokenRecord)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Unable to create access token",
		})
		return
	}

	err = manager.Vault.CreateRefreshToken(refreshTokenRecord)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Unable to create refresh token",
		})
		return
	}

	// Return token response
	response := map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"scope":         strings.Join(authCode.Scopes, " "),
	}

	writeJSON(w, http.StatusOK, response)
}

func handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, cfg *Config) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	refreshTokenStr := r.FormValue("refresh_token")

	// Validate client
	client, err := manager.Vault.GetClient(clientID)
	if err != nil || client.ClientSecret != clientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_client",
			"error_description": "Client authentication failed",
		})
		return
	}

	// Validate refresh token
	refreshToken, err := manager.Vault.GetRefreshToken(refreshTokenStr)
	if err != nil || refreshToken.ExpiresAt.Before(time.Now()) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "Refresh token is invalid or expired",
		})
		return
	}

	if refreshToken.ClientID != clientID {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "Refresh token was not issued to this client",
		})
		return
	}

	// Generate new access token
	accessToken := generateRandomString(32)

	// Get user info to determine scopes
	userInfo, err := manager.Vault.GetUserInfoByUsername(refreshToken.UserID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Unable to get user information",
		})
		return
	}

	// Use client's default scopes
	scopes := client.Scopes

	// Store new access token
	accessTokenRecord := &AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    userInfo.UserID,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err = manager.Vault.CreateAccessToken(accessTokenRecord)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Unable to create access token",
		})
		return
	}

	// Return token response
	response := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        strings.Join(scopes, " "),
	}

	writeJSON(w, http.StatusOK, response)
}

func oauthUserInfoHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract access token
		auth := r.Header.Get("Authorization")
		if auth == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_request",
				"error_description": "Access token required",
			})
			return
		}

		var accessToken string
		if strings.HasPrefix(auth, "Bearer ") {
			accessToken = auth[7:]
		} else {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_request",
				"error_description": "Invalid authorization header format",
			})
			return
		}

		// Validate access token
		tokenRecord, err := manager.Vault.GetAccessToken(accessToken)
		if err != nil || tokenRecord.ExpiresAt.Before(time.Now()) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "Access token is invalid or expired",
			})
			return
		}

		// Get user info
		userInfo, err := manager.Vault.GetUserInfoByUsername(tokenRecord.UserID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":             "server_error",
				"error_description": "Unable to get user information",
			})
			return
		}

		// Return user info based on granted scopes
		response := make(map[string]any)

		for _, scope := range tokenRecord.Scopes {
			switch scope {
			case "profile":
				response["sub"] = userInfo.UserID
				response["username"] = userInfo.Username
			case "email":
				response["email"] = userInfo.Username
				response["email_verified"] = true
			}
		}

		writeJSON(w, http.StatusOK, response)
	}
}

// Client management handlers
func clientRegistrationHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			manager.renderTemplate(w, "client-registration.html", map[string]any{
				"Config": cfg,
			})
			return
		}

		if r.Method == http.MethodPost {
			// Parse form data
			name := r.FormValue("name")
			redirectURIs := strings.Split(r.FormValue("redirect_uris"), "\n")
			scopes := r.Form["scopes"]

			if name == "" || len(redirectURIs) == 0 {
				renderErrorPage(w, http.StatusBadRequest, "Invalid Request",
					"Name and redirect URIs are required.",
					"Please fill in all required fields.",
					"Missing required fields", "/oauth/clients/register")
				return
			}

			// Clean redirect URIs
			var cleanRedirectURIs []string
			for _, uri := range redirectURIs {
				uri = strings.TrimSpace(uri)
				if uri != "" {
					cleanRedirectURIs = append(cleanRedirectURIs, uri)
				}
			}

			// Generate client credentials
			clientID := generateRandomString(32)
			clientSecret := generateRandomString(64)

			client := &Client{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Name:         name,
				RedirectURIs: cleanRedirectURIs,
				Scopes:       scopes,
				IsApproved:   !cfg.ClientRegistration.RequireApproval,
			}

			err := manager.Vault.CreateClient(client)
			if err != nil {
				renderErrorPage(w, http.StatusInternalServerError, "Server Error",
					"Unable to create client application.",
					"Please try again later.",
					fmt.Sprintf("Failed to create client: %v", err), "/oauth/clients/register")
				return
			}

			manager.renderTemplate(w, "client-created.html", map[string]any{
				"Client":          client,
				"RequireApproval": cfg.ClientRegistration.RequireApproval,
			})
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}
