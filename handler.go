package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oarkflow/paseto/token"
	"github.com/oarkflow/xid/wuid"
	"golang.org/x/crypto/bcrypt"
)

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

// --- SSO Handler ---
func ssoHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Query().Get("token") == "" {
			manager.renderTemplate(w, "sso.html", nil)
			return
		}

		if r.Method == "POST" {
			if err := r.ParseForm(); err != nil {
				renderErrorPage(w, http.StatusBadRequest, "Invalid Form Data",
					"The SSO form data could not be processed.",
					"Please check your input and try again.",
					fmt.Sprintf("ParseForm error: %v", err), "/sso")
				return
			}
			username := r.FormValue("username")
			tokenStr := r.FormValue("token")
			if username == "" || tokenStr == "" {
				renderErrorPage(w, http.StatusBadRequest, "Missing SSO Information",
					"Username and token are required for SSO login.",
					"Please provide both username and authentication token.",
					"Missing username or token in SSO request", "/sso")
				return
			}
			info, exists := lookupUserByUsername(username)
			if !exists {
				renderErrorPage(w, http.StatusNotFound, "User Not Found",
					"The specified username is not registered in our system.",
					"Please check your username or register for a new account first.",
					fmt.Sprintf("Username '%s' not found in database", username), "/register")
				return
			}

			// Check if user has "simple" login type - they cannot use SSO tokens from secured login
			if info.LoginType == "simple" {
				renderErrorPage(w, http.StatusForbidden, "Simple Login Required",
					"Your account is configured for simple username/password login.",
					"Please use the simple login option with your username and password.",
					"User account configured for simple login only", "/simple-login")
				return
			}

			decTok, err := token.DecryptToken(tokenStr, cfg.PasetoSecret)
			if err != nil {
				renderErrorPage(w, http.StatusUnauthorized, "Invalid Authentication Token",
					"The provided authentication token is invalid or corrupted.",
					"Please request a new authentication token and try again.",
					fmt.Sprintf("Token decryption failed: %v", err), "/login")
				return
			}
			claims := decTok.Claims
			sub, _ := claims["sub"].(string)
			// --- FIX: Compare sub with stored public key from credentials ---
			storedPubX, storedPubY, err := getPublicKeyByUserID(info.UserID)
			if err != nil {
				renderErrorPage(w, http.StatusUnauthorized, "User Key Not Found",
					"Could not retrieve cryptographic key for this user.",
					"There's an issue with your account's security keys. Please contact support.",
					fmt.Sprintf("Public key retrieval failed for user %s: %v", info.UserID, err), "/login")
				return
			}
			if sub != storedPubX+":"+storedPubY {
				renderErrorPage(w, http.StatusUnauthorized, "Token Mismatch",
					"The authentication token does not match the specified username.",
					"This token was issued for a different user account.",
					"Token subject does not match stored public key", "/login")
				return
			}
			// Blacklist check
			if manager.IsTokenDenylisted(tokenStr) {
				renderErrorPage(w, http.StatusUnauthorized, "Session Terminated",
					"This authentication token has been logged out.",
					"Please log in again to access your account.",
					"Token found in logout denylist", "/login")
				return
			}
			ctx := context.WithValue(r.Context(), "user", claims["sub"])

			// Clear any previous logout state for SSO login
			initUserLogoutTracker()
			if sub, ok := claims["sub"].(string); ok {
				if userInfo, exists := lookupUserByPubHex(sub); exists {
					userLogoutTracker.ClearUserLogout(userInfo.UserID)
				}
			}

			http.SetCookie(w, getCookie(tokenStr))
			http.Redirect(w, r.WithContext(ctx), "/protected", http.StatusSeeOther)
			return
		}

		// GET with token in URL
		tokenStr := r.URL.Query().Get("token")
		if tokenStr == "" {
			renderErrorPage(w, http.StatusBadRequest, "Missing Authentication Token",
				"No authentication token was provided in the SSO request.",
				"Please use a valid SSO link with an authentication token.",
				"Missing token parameter in SSO URL", "/login")
			return
		}
		decTok, err := token.DecryptToken(tokenStr, cfg.PasetoSecret)
		if err != nil {
			renderErrorPage(w, http.StatusUnauthorized, "Invalid SSO Token",
				"The SSO authentication token is invalid or corrupted.",
				"Please request a new SSO link and try again.",
				fmt.Sprintf("SSO token decryption failed: %v", err), "/login")
			return
		}
		claims := decTok.Claims
		if manager.IsTokenDenylisted(tokenStr) {
			renderErrorPage(w, http.StatusUnauthorized, "Session Already Terminated",
				"This authentication token has been logged out.",
				"Please log in again to access your account.",
				"SSO token found in logout denylist", "/login")
			return
		}
		ctx := context.WithValue(r.Context(), "user", claims["sub"])

		// Clear any previous logout state for SSO token login
		initUserLogoutTracker()
		if sub, ok := claims["sub"].(string); ok {
			if userInfo, exists := lookupUserByPubHex(sub); exists {
				userLogoutTracker.ClearUserLogout(userInfo.UserID)
			}
		}

		http.SetCookie(w, getCookie(tokenStr))
		http.Redirect(w, r.WithContext(ctx), "/protected", http.StatusSeeOther)
	}
}

// --- Logout Handler ---
func logoutHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// Check if this is a logout success redirect
			success := r.URL.Query().Get("success")
			manager.renderTemplate(w, "logout.html", map[string]any{
				"Success": success == "1",
			})
			return
		}
		tokenStr := ""
		cookie, err := r.Cookie("session_token")
		if err == nil {
			tokenStr = cookie.Value
		} else if r.Header.Get("Authorization") != "" {
			tokenStr = r.Header.Get("Authorization")
		}
		if tokenStr == "" {
			renderErrorPage(w, http.StatusBadRequest, "No Authentication Token",
				"No authentication token found for logout.",
				"You don't appear to be logged in. Please log in first if you want to access protected areas.",
				"No session_token cookie or Authorization header found", "/login")
			return
		}
		decTok, err := token.DecryptToken(tokenStr, cfg.PasetoSecret)
		if err != nil {
			renderErrorPage(w, http.StatusBadRequest, "Invalid Authentication Token",
				"The authentication token could not be processed for logout.",
				"Your session may have been corrupted. Please try logging in again.",
				fmt.Sprintf("Token decryption failed during logout: %v", err), "/login")
			return
		}
		exp, _ := decTok.Claims["exp"].(int64)
		if exp == 0 {
			// fallback for float64
			if expf, ok := decTok.Claims["exp"].(float64); ok {
				exp = int64(expf)
			}
		}
		manager.CleanupExpiredTokens()
		manager.AddTokenToDenylist(tokenStr, exp)

		// CRITICAL SECURITY: Also logout from proof-based authentication
		// Extract user ID from token to invalidate proof-based access
		if sub, ok := decTok.Claims["sub"].(string); ok {
			if userInfo, exists := lookupUserByPubHex(sub); exists {
				// Initialize logout tracker if needed
				initUserLogoutTracker()
				// Set user as logged out for proof-based auth
				userLogoutTracker.SetUserLogout(userInfo.UserID)
			}
		}

		http.SetCookie(w, getCookie("", -1))

		// Add cache control headers to prevent browser caching
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		// Redirect to logout confirmation page
		http.Redirect(w, r, "/logout?success=1", http.StatusSeeOther)
	}
}

// --- Authentication Handlers ---
// Secured Login Handler - Cryptographic proof-based authentication
func loginHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			manager.renderTemplate(w, "secured-login.html", nil)
			return
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			renderErrorPage(w, http.StatusBadRequest, "Invalid Form Data",
				"The login form data could not be processed.",
				"Please check that your key file is properly formatted and try again.",
				fmt.Sprintf("ParseMultipartForm error: %v", err), "/secured-login")
			return
		}
		file, _, err := r.FormFile("keyfile")
		if err != nil {
			renderErrorPage(w, http.StatusBadRequest, "Missing Key File",
				"No cryptographic key file was provided.",
				"Please select your .json key file that was downloaded during registration.",
				fmt.Sprintf("FormFile error: %v", err), "/secured-login")
			return
		}
		defer file.Close()
		var keyData map[string]string
		if err := json.NewDecoder(file).Decode(&keyData); err != nil {
			log.Printf("Key file decode error: %v", err)
			renderErrorPage(w, http.StatusBadRequest, "Invalid Key File Format",
				"The key file could not be read or is not in the correct format.",
				"Please ensure you're using the correct .json key file that was downloaded during registration.",
				fmt.Sprintf("JSON decode error: %v", err), "/secured-login")
			return
		}
		pubx, ok1 := keyData["PubKeyX"]
		puby, ok2 := keyData["PubKeyY"]
		encPrivD, ok3 := keyData["EncryptedPrivateKeyD"]
		if !ok1 || !ok2 || !ok3 {
			renderErrorPage(w, http.StatusBadRequest, "Incomplete Key File",
				"The key file is missing required cryptographic data.",
				"Please ensure you're using the complete, unmodified key file from registration.",
				"Missing PubKeyX, PubKeyY, or EncryptedPrivateKeyD fields", "/secured-login")
			return
		}
		password := r.FormValue("password")
		if password == "" {
			renderErrorPage(w, http.StatusBadRequest, "Missing Password",
				"Password is required to decrypt your private key.",
				"Please enter the password you used during registration.",
				"Password field is empty", "/secured-login")
			return
		}

		// Phase 1: Add rate limiting for secured login
		clientIP := getClientIP(r)
		pubHex := pubx + ":" + puby
		loginIdentifier := fmt.Sprintf("%s:%s", clientIP, pubHex)

		// Check if login is blocked for this key/IP combination
		if manager.Security.IsLoginBlocked(loginIdentifier) {
			renderErrorPage(w, http.StatusTooManyRequests, "Login Temporarily Blocked",
				"Too many failed login attempts.",
				fmt.Sprintf("Please wait %d minutes before trying again.", int(loginCooldownPeriod.Minutes())),
				fmt.Sprintf("Login blocked for key %s from %s", pubHex[:16]+"...", clientIP), "/secured-login")
			return
		}

		info, exists := lookupUserByPubHex(pubHex)
		if !exists {
			// Phase 1: Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Unrecognized Key",
				"This cryptographic key is not associated with any registered user.",
				"Please check that you're using the correct key file, or register for a new account.",
				"Public key not found in user registry", "/register")
			return
		}

		// Check if user has "simple" login type - they cannot use secured login
		if info.LoginType == "simple" {
			renderErrorPage(w, http.StatusForbidden, "Simple Login Required",
				"Your account is configured for simple username/password login.",
				"Please use the simple login option with your username and password.",
				"User account configured for simple login only", "/simple-login")
			return
		}

		// Validate public key from credentials table
		storedPubX, storedPubY, err := getPublicKeyByUserID(info.UserID)
		if err != nil || storedPubX != pubx || storedPubY != puby {
			// Phase 1: Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Key Validation Failed",
				"The cryptographic key does not match our stored credentials.",
				"There may be an issue with your key file or account. Please contact support.",
				"Public key mismatch with stored credentials", "/secured-login")
			return
		}
		passwordHash, err := manager.Vault.GetUserSecret(info.UserID)
		if err != nil {
			// Phase 1: Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Account Verification Failed",
				"Could not verify your account password.",
				"There may be an issue with your account setup. Please contact support.",
				fmt.Sprintf("Password hash retrieval failed: %v", err), "/secured-login")
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			// Phase 1: Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Incorrect Password",
				"The password you entered is incorrect.",
				"Please check your password and try again. This should be the same password you used during registration.",
				"Password verification failed", "/secured-login")
			return
		}
		privD := decryptPrivateKeyD(encPrivD, password)
		if _, err := hex.DecodeString(privD); err != nil {
			log.Printf("Decrypted PrivateKeyD is not valid hex: %v", err)
			renderErrorPage(w, http.StatusUnauthorized, "Key Decryption Failed",
				"Could not decrypt your private key with the provided password.",
				"Please check that you're using the correct password and key file combination.",
				"Private key decryption failed or result is invalid hex", "/secured-login")
			return
		}
		nonce, ts := getNonceWithTimestamp()
		proof := generateProof(privD, nonce, ts)
		if err := verifyProofWithReplay(&proof); err != nil {
			// Phase 1: Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Cryptographic Proof Failed",
				"The cryptographic proof verification failed.",
				"There was an issue with the authentication process. Please try again.",
				fmt.Sprintf("Proof verification failed: %v", err), "/secured-login")
			return
		}

		// Phase 1: Clear failed login attempts on successful authentication
		manager.Security.ClearLoginAttempts(loginIdentifier)
		claims := getClaims(pubHex, nonce, ts)
		t := token.CreateToken(expDuration, token.AlgEncrypt)
		_ = token.RegisterClaims(t, claims)
		tokenStr, err := token.EncryptToken(t, cfg.PasetoSecret)
		if err != nil {
			renderErrorPage(w, http.StatusInternalServerError, "Token Generation Failed",
				"Failed to generate authentication token.",
				"There was an internal error during login. Please try again.",
				fmt.Sprintf("PASETO token encryption failed: %v", err), "/secured-login")
			return
		}
		link := fmt.Sprintf("http://localhost%s/sso?token=%s", cfg.Addr, tokenStr)
		fmt.Printf("SSO link for %s: %s\n", info.Username, link)
		fmt.Fprintf(w, "SSO login link generated! Check terminal for demo link.")
	}
}

// Simple Login Handler - Username/Password authentication
func simpleLoginHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			manager.renderTemplate(w, "simple-login.html", nil)
			return
		}

		if err := r.ParseForm(); err != nil {
			renderErrorPage(w, http.StatusBadRequest, "Invalid Form Data",
				"The login form data could not be processed.",
				"Please check your input and try again.",
				fmt.Sprintf("ParseForm error: %v", err), "/simple-login")
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		// OAuth parameters
		clientID := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		scope := r.FormValue("scope")
		state := r.FormValue("state")

		if username == "" || password == "" {
			renderErrorPage(w, http.StatusBadRequest, "Missing Login Information",
				"Username and password are required for login.",
				"Please provide both your username and password.",
				"Missing username or password fields", "/simple-login")
			return
		}

		// Enhanced input validation and sanitization
		username = sanitizeInput(username)
		clientIP := getClientIP(r)
		loginIdentifier := fmt.Sprintf("%s:%s", clientIP, username)

		// Check if login is blocked for this user/IP combination
		if manager.Security.IsLoginBlocked(loginIdentifier) {
			renderErrorPage(w, http.StatusTooManyRequests, "Login Temporarily Blocked",
				"Too many failed login attempts.",
				fmt.Sprintf("Please wait %d minutes before trying again.", int(loginCooldownPeriod.Minutes())),
				fmt.Sprintf("Login blocked for %s from %s", username, clientIP), "/simple-login")
			return
		}

		// Lookup user by username
		info, exists := lookupUserByUsername(username)
		if !exists {
			// Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Invalid Credentials",
				"The username or password you entered is incorrect.",
				"Please check your credentials and try again, or register for a new account.",
				"Username not found in database", "/simple-login")
			return
		}

		// Check if user has "secured" login type - they cannot use simple login
		if info.LoginType == "secured" {
			renderErrorPage(w, http.StatusForbidden, "Secured Login Required",
				"Your account requires secured login with cryptographic key.",
				"Please use the secured login option and provide your cryptographic key.",
				"User account configured for secured login only", "/secured-login")
			return
		}

		// Get stored password hash
		passwordHash, err := manager.Vault.GetUserSecret(info.UserID)
		if err != nil {
			// Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Invalid Credentials",
				"The username or password you entered is incorrect.",
				"Please check your credentials and try again, or register for a new account.",
				"Password hash not found for user", "/simple-login")
			return
		}

		// Verify password
		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			// Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Invalid Credentials",
				"The username or password you entered is incorrect.",
				"Please check your credentials and try again.",
				"Password verification failed", "/simple-login")
			return
		}

		// Clear failed login attempts on successful login
		manager.Security.ClearLoginAttempts(loginIdentifier)

		// Get public key for token creation
		pubKeyX, pubKeyY, err := getPublicKeyByUserID(info.UserID)
		if err != nil {
			renderErrorPage(w, http.StatusInternalServerError, "Account Key Error",
				"Could not retrieve your account's cryptographic keys.",
				"There's an issue with your account setup. Please contact support.",
				fmt.Sprintf("Public key retrieval failed: %v", err), "/simple-login")
			return
		}

		pubHex := pubKeyX + ":" + pubKeyY
		nonce, ts := getNonceWithTimestamp()

		// Create token claims
		claims := getClaims(pubHex, nonce, ts)

		// Create PASETO token
		t := token.CreateToken(expDuration, token.AlgEncrypt)
		_ = token.RegisterClaims(t, claims)
		tokenStr, err := token.EncryptToken(t, cfg.PasetoSecret)
		if err != nil {
			renderErrorPage(w, http.StatusInternalServerError, "Login Token Error",
				"Failed to create authentication token.",
				"There was an internal error during login. Please try again.",
				fmt.Sprintf("PASETO token encryption failed: %v", err), "/simple-login")
			return
		}

		// Set cookie and clear any previous logout state for simple login
		initUserLogoutTracker()
		if userInfo, exists := lookupUserByUsername(username); exists {
			userLogoutTracker.ClearUserLogout(userInfo.UserID)
		}
		http.SetCookie(w, getCookie(tokenStr))

		// Handle OAuth flow or regular login
		if clientID != "" && redirectURI != "" {
			// OAuth authorization flow
			authURL := fmt.Sprintf("/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code",
				url.QueryEscape(clientID), url.QueryEscape(redirectURI))
			if scope != "" {
				authURL += "&scope=" + url.QueryEscape(scope)
			}
			if state != "" {
				authURL += "&state=" + url.QueryEscape(state)
			}
			http.Redirect(w, r, authURL, http.StatusFound)
		} else {
			// Regular login - redirect to protected area
			http.Redirect(w, r, "/protected", http.StatusSeeOther)
		}
	}
}

// Secured Login Handler - Cryptographic proof-based authentication
func securedLoginHandler(cfg *Config) http.HandlerFunc {
	return loginHandler(cfg) // Use existing sophisticated login
}

// Login selection handler
func loginSelectionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Show username form to determine login type
		manager.renderTemplate(w, "login-selection.html", nil)
		return
	}

	// POST - Check username and redirect to appropriate login form
	if err := r.ParseForm(); err != nil {
		renderErrorPage(w, http.StatusBadRequest, "Invalid Form Data",
			"The form data could not be processed.",
			"Please check your input and try again.",
			fmt.Sprintf("ParseForm error: %v", err), "/login")
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	if username == "" {
		renderErrorPage(w, http.StatusBadRequest, "Missing Username",
			"Username is required to determine your login method.",
			"Please provide your username (email or phone number).",
			"Missing username field", "/login")
		return
	}

	// Validate username format
	username = sanitizeInput(username)
	var validationErr error
	if isEmail(username) {
		validationErr = validateEmail(username)
	} else if isPhone(username) {
		validationErr = validatePhone(username)
	} else {
		validationErr = fmt.Errorf("username must be a valid email address or phone number")
	}

	if validationErr != nil {
		renderErrorPage(w, http.StatusBadRequest, "Invalid Username Format",
			"The username you provided is not valid.",
			validationErr.Error(),
			validationErr.Error(), "/login")
		return
	}

	// Check if user exists
	userInfo, hasUser := lookupUserByUsername(username)
	if !hasUser {
		renderErrorPage(w, http.StatusNotFound, "User Not Found",
			"No account found with that username.",
			"Please check your username or register for a new account.",
			fmt.Sprintf("Username '%s' not found", username), "/register")
		return
	}

	// Based on user's login type, show appropriate login form
	if userInfo.LoginType == "simple" {
		// Show simple login form with just password
		manager.renderTemplate(w, "simple-login.html", map[string]any{
			"Username": username,
			"UserInfo": userInfo,
		})
	} else {
		// Show secured login form
		manager.renderTemplate(w, "secured-login.html", map[string]any{
			"Username": username,
			"UserInfo": userInfo,
		})
	}
}

// Process simple login from unified login form
func processSimpleLoginHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if err := r.ParseForm(); err != nil {
			renderErrorPage(w, http.StatusBadRequest, "Invalid Form Data",
				"The login form data could not be processed.",
				"Please check your input and try again.",
				fmt.Sprintf("ParseForm error: %v", err), "/login")
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		// OAuth parameters
		clientID := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		scope := r.FormValue("scope")
		state := r.FormValue("state")

		if username == "" || password == "" {
			renderErrorPage(w, http.StatusBadRequest, "Missing Login Information",
				"Username and password are required for login.",
				"Please provide both your username and password.",
				"Missing username or password fields", "/login")
			return
		}

		// Enhanced input validation and sanitization
		username = sanitizeInput(username)
		clientIP := getClientIP(r)
		loginIdentifier := fmt.Sprintf("%s:%s", clientIP, username)

		// Check if login is blocked for this user/IP combination
		if manager.Security.IsLoginBlocked(loginIdentifier) {
			renderErrorPage(w, http.StatusTooManyRequests, "Login Temporarily Blocked",
				"Too many failed login attempts.",
				fmt.Sprintf("Please wait %d minutes before trying again.", int(loginCooldownPeriod.Minutes())),
				fmt.Sprintf("Login blocked for %s from %s", username, clientIP), "/login")
			return
		}

		// Lookup user by username
		info, exists := lookupUserByUsername(username)
		if !exists {
			// Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Invalid Credentials",
				"The username or password you entered is incorrect.",
				"Please check your credentials and try again, or register for a new account.",
				"Username not found in database", "/login")
			return
		}

		// Check if user has "secured" login type - they cannot use simple login
		if info.LoginType == "secured" {
			renderErrorPage(w, http.StatusForbidden, "Secured Login Required",
				"Your account requires secured login with cryptographic key.",
				"Please use the secured login option and provide your cryptographic key.",
				"User account configured for secured login only", "/login")
			return
		}

		// Get stored password hash
		passwordHash, err := manager.Vault.GetUserSecret(info.UserID)
		if err != nil {
			// Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Invalid Credentials",
				"The username or password you entered is incorrect.",
				"Please check your credentials and try again, or register for a new account.",
				"Password hash not found for user", "/login")
			return
		}

		// Verify password
		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			// Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Invalid Credentials",
				"The username or password you entered is incorrect.",
				"Please check your credentials and try again.",
				"Password verification failed", "/login")
			return
		}

		// Clear failed login attempts on successful login
		manager.Security.ClearLoginAttempts(loginIdentifier)

		// Get public key for token creation
		pubKeyX, pubKeyY, err := getPublicKeyByUserID(info.UserID)
		if err != nil {
			renderErrorPage(w, http.StatusInternalServerError, "Account Key Error",
				"Could not retrieve your account's cryptographic keys.",
				"There's an issue with your account setup. Please contact support.",
				fmt.Sprintf("Public key retrieval failed: %v", err), "/login")
			return
		}

		pubHex := pubKeyX + ":" + pubKeyY
		nonce, ts := getNonceWithTimestamp()

		// Create token claims
		claims := getClaims(pubHex, nonce, ts)

		// Create PASETO token
		t := token.CreateToken(expDuration, token.AlgEncrypt)
		_ = token.RegisterClaims(t, claims)
		tokenStr, err := token.EncryptToken(t, cfg.PasetoSecret)
		if err != nil {
			renderErrorPage(w, http.StatusInternalServerError, "Login Token Error",
				"Failed to create authentication token.",
				"There was an internal error during login. Please try again.",
				fmt.Sprintf("PASETO token encryption failed: %v", err), "/login")
			return
		}

		// Set cookie and clear any previous logout state for simple login
		initUserLogoutTracker()
		if userInfo, exists := lookupUserByUsername(username); exists {
			userLogoutTracker.ClearUserLogout(userInfo.UserID)
		}
		http.SetCookie(w, getCookie(tokenStr))

		// Handle OAuth flow or regular login
		if clientID != "" && redirectURI != "" {
			// OAuth authorization flow
			authURL := fmt.Sprintf("/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code",
				url.QueryEscape(clientID), url.QueryEscape(redirectURI))
			if scope != "" {
				authURL += "&scope=" + url.QueryEscape(scope)
			}
			if state != "" {
				authURL += "&state=" + url.QueryEscape(state)
			}
			http.Redirect(w, r, authURL, http.StatusFound)
		} else {
			// Regular login - redirect to protected area
			http.Redirect(w, r, "/protected", http.StatusSeeOther)
		}
	}
}

// Process secured login from unified login form
func processSecuredLoginHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if err := r.ParseMultipartForm(1 << 20); err != nil {
			renderErrorPage(w, http.StatusBadRequest, "Invalid Form Data",
				"The login form data could not be processed.",
				"Please check that your key file is properly formatted and try again.",
				fmt.Sprintf("ParseMultipartForm error: %v", err), "/login")
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		file, _, err := r.FormFile("keyfile")
		if err != nil {
			renderErrorPage(w, http.StatusBadRequest, "Missing Key File",
				"No cryptographic key file was provided.",
				"Please select your .json key file that was downloaded during registration.",
				fmt.Sprintf("FormFile error: %v", err), "/login")
			return
		}
		defer file.Close()

		var keyData map[string]string
		if err := json.NewDecoder(file).Decode(&keyData); err != nil {
			log.Printf("Key file decode error: %v", err)
			renderErrorPage(w, http.StatusBadRequest, "Invalid Key File Format",
				"The key file could not be read or is not in the correct format.",
				"Please ensure you're using the correct .json key file that was downloaded during registration.",
				fmt.Sprintf("JSON decode error: %v", err), "/login")
			return
		}

		pubx, ok1 := keyData["PubKeyX"]
		puby, ok2 := keyData["PubKeyY"]
		encPrivD, ok3 := keyData["EncryptedPrivateKeyD"]
		if !ok1 || !ok2 || !ok3 {
			renderErrorPage(w, http.StatusBadRequest, "Incomplete Key File",
				"The key file is missing required cryptographic data.",
				"Please ensure you're using the complete, unmodified key file from registration.",
				"Missing PubKeyX, PubKeyY, or EncryptedPrivateKeyD fields", "/login")
			return
		}

		password := r.FormValue("password")
		if password == "" {
			renderErrorPage(w, http.StatusBadRequest, "Missing Password",
				"Password is required to decrypt your private key.",
				"Please enter the password you used during registration.",
				"Password field is empty", "/login")
			return
		}

		// Phase 1: Add rate limiting for secured login
		clientIP := getClientIP(r)
		pubHex := pubx + ":" + puby
		loginIdentifier := fmt.Sprintf("%s:%s", clientIP, pubHex)

		// Check if login is blocked for this key/IP combination
		if manager.Security.IsLoginBlocked(loginIdentifier) {
			renderErrorPage(w, http.StatusTooManyRequests, "Login Temporarily Blocked",
				"Too many failed login attempts.",
				fmt.Sprintf("Please wait %d minutes before trying again.", int(loginCooldownPeriod.Minutes())),
				fmt.Sprintf("Login blocked for key %s from %s", pubHex[:16]+"...", clientIP), "/login")
			return
		}

		info, exists := lookupUserByPubHex(pubHex)
		if !exists {
			// Phase 1: Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Unrecognized Key",
				"This cryptographic key is not associated with any registered user.",
				"Please check that you're using the correct key file, or register for a new account.",
				"Public key not found in user registry", "/register")
			return
		}

		// Verify this matches the username provided
		if info.Username != username {
			renderErrorPage(w, http.StatusUnauthorized, "Username/Key Mismatch",
				"The cryptographic key does not belong to the specified username.",
				"Please ensure you're using the correct key file for this account.",
				"Username does not match key owner", "/login")
			return
		}

		// Check if user has "simple" login type - they cannot use secured login
		if info.LoginType == "simple" {
			renderErrorPage(w, http.StatusForbidden, "Simple Login Required",
				"Your account is configured for simple username/password login.",
				"Please use the simple login option with your username and password.",
				"User account configured for simple login only", "/login")
			return
		}

		// Validate public key from credentials table
		storedPubX, storedPubY, err := getPublicKeyByUserID(info.UserID)
		if err != nil || storedPubX != pubx || storedPubY != puby {
			// Phase 1: Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Key Validation Failed",
				"The cryptographic key does not match our stored credentials.",
				"There may be an issue with your key file or account. Please contact support.",
				"Public key mismatch with stored credentials", "/login")
			return
		}

		passwordHash, err := manager.Vault.GetUserSecret(info.UserID)
		if err != nil {
			// Phase 1: Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Account Verification Failed",
				"Could not verify your account password.",
				"There may be an issue with your account setup. Please contact support.",
				fmt.Sprintf("Password hash retrieval failed: %v", err), "/login")
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			// Phase 1: Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Incorrect Password",
				"The password you entered is incorrect.",
				"Please check your password and try again. This should be the same password you used during registration.",
				"Password verification failed", "/login")
			return
		}

		privD := decryptPrivateKeyD(encPrivD, password)
		if _, err := hex.DecodeString(privD); err != nil {
			log.Printf("Decrypted PrivateKeyD is not valid hex: %v", err)
			renderErrorPage(w, http.StatusUnauthorized, "Key Decryption Failed",
				"Could not decrypt your private key with the provided password.",
				"Please check that you're using the correct password and key file combination.",
				"Private key decryption failed or result is invalid hex", "/login")
			return
		}

		nonce, ts := getNonceWithTimestamp()
		proof := generateProof(privD, nonce, ts)
		if err := verifyProofWithReplay(&proof); err != nil {
			// Phase 1: Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Cryptographic Proof Failed",
				"The cryptographic proof verification failed.",
				"There was an issue with the authentication process. Please try again.",
				fmt.Sprintf("Proof verification failed: %v", err), "/login")
			return
		}

		// Phase 1: Clear failed login attempts on successful authentication
		manager.Security.ClearLoginAttempts(loginIdentifier)
		claims := getClaims(pubHex, nonce, ts)
		t := token.CreateToken(expDuration, token.AlgEncrypt)
		_ = token.RegisterClaims(t, claims)
		tokenStr, err := token.EncryptToken(t, cfg.PasetoSecret)
		if err != nil {
			renderErrorPage(w, http.StatusInternalServerError, "Token Generation Failed",
				"Failed to generate authentication token.",
				"There was an internal error during login. Please try again.",
				fmt.Sprintf("PASETO token encryption failed: %v", err), "/login")
			return
		}

		// Set cookie and redirect to protected area
		http.SetCookie(w, getCookie(tokenStr))
		http.Redirect(w, r, "/protected", http.StatusSeeOther)
	}
}
func apiStatusHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "online",
		"version":   "1.0.0",
		"features":  []string{"simple-login", "secured-login", "ecdsa-signatures", "paseto-tokens"},
		"timestamp": time.Now().Unix(),
	})
}

func apiUserInfoHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "no authentication token provided",
			})
			return
		}

		// Check if token is in logout denylist
		manager.CleanupExpiredTokens()
		if manager.IsTokenDenylisted(tokenStr) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "token has been logged out",
			})
			return
		}

		decTok, err := token.DecryptToken(tokenStr, cfg.PasetoSecret)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid token",
			})
			return
		}

		claims := decTok.Claims
		pubHex, _ := claims["sub"].(string)
		info, exists := lookupUserByPubHex(pubHex)
		if !exists {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error": "user not found",
			})
			return
		}

		// Get public key details
		pubKeyX, pubKeyY, err := getPublicKeyByUserID(info.UserID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "failed to retrieve user keys",
			})
			return
		}

		iat, _ := claims["iat"].(float64)
		exp_claim, _ := claims["exp"].(float64)

		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"user": map[string]any{
				"id":         info.UserID,
				"username":   info.Username,
				"login_type": info.LoginType,
				"pubKeyX":    pubKeyX,
				"pubKeyY":    pubKeyY,
				"pubHex":     pubHex,
			},
			"session": map[string]any{
				"issuedAt":  int64(iat),
				"expiresAt": int64(exp_claim),
				"timeLeft":  int64(exp_claim) - time.Now().Unix(),
			},
		})
	}
}

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

// Simple login API endpoint (for frontend integration)
func apiSimpleLoginHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
				"error": "method not allowed",
			})
			return
		}

		var loginReq struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid JSON payload",
			})
			return
		}

		if loginReq.Username == "" || loginReq.Password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "username and password are required",
			})
			return
		}

		// Lookup user
		info, exists := lookupUserByUsername(loginReq.Username)
		if !exists {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid credentials",
			})
			return
		}

		// Check if user has "secured" login type - they cannot use simple login
		if info.LoginType == "secured" {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "access denied: your account requires secured login with cryptographic key file",
			})
			return
		}

		// Verify password
		passwordHash, err := manager.Vault.GetUserSecret(info.UserID)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid credentials",
			})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(loginReq.Password)); err != nil {

			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid credentials",
			})
			return
		}

		// Get public key for token
		pubKeyX, pubKeyY, err := getPublicKeyByUserID(info.UserID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "failed to retrieve user keys",
			})
			return
		}

		pubHex := pubKeyX + ":" + pubKeyY
		nonce, ts := getNonceWithTimestamp()

		// Create token
		claims := getClaims(pubHex, nonce, ts)
		t := token.CreateToken(expDuration, token.AlgEncrypt)
		_ = token.RegisterClaims(t, claims)
		tokenStr, err := token.EncryptToken(t, cfg.PasetoSecret)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "failed to create token",
			})
			return
		}

		// Set cookie and clear any previous logout state for API login
		initUserLogoutTracker()
		userLogoutTracker.ClearUserLogout(info.UserID)
		http.SetCookie(w, getCookie(tokenStr))

		writeJSON(w, http.StatusOK, map[string]any{
			"success": true,
			"token":   tokenStr,
			"user": map[string]any{
				"id":       info.UserID,
				"username": info.Username,
				"pubHex":   pubHex,
			},
			"expiresAt": time.Now().Add(expDuration).Unix(),
		})
	}
}

func protectedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pubHex, _ := r.Context().Value("user").(string)
		info, _ := lookupUserByPubHex(pubHex)
		manager.renderTemplate(w, "protected.html", map[string]any{
			"PubHex":   pubHex,
			"DBUserID": info.UserID,
			"Username": info.Username,
		})
	})
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

// --- Error Handling ---
func renderErrorPage(w http.ResponseWriter, statusCode int, title, message, description, technical, retryURL string) {
	// Generate unique error ID
	errorID := fmt.Sprintf("ERR-%d-%d", time.Now().Unix(), statusCode)

	data := ErrorPageData{
		Title:       title,
		StatusCode:  statusCode,
		Message:     message,
		Description: description,
		Technical:   technical,
		RetryURL:    retryURL,
		ErrorID:     errorID,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := manager.Templates.ExecuteTemplate(w, "error.html", data); err != nil {
		// Fallback to plain text error if template fails
		http.Error(w, message, statusCode)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	manager.renderTemplate(w, "index.html", nil)
}

func apiDemoHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "api-demo.html")
}

// --- Basic Handlers ---
func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func nonce(w http.ResponseWriter, _ *http.Request) {
	nonce, timestamp := getNonceWithTimestamp()
	writeJSON(w, http.StatusOK, map[string]any{
		"nonce":     nonce,
		"timestamp": timestamp,
	})
}

// --- Password Reset Handlers ---
func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		manager.renderTemplate(w, "forgot-password.html", nil)
		return
	}

	if err := r.ParseForm(); err != nil {
		renderErrorPage(w, http.StatusBadRequest, "Invalid Form Data",
			"The form data you submitted could not be processed.",
			"Please check that all required fields are filled correctly and try again.",
			fmt.Sprintf("ParseForm error: %v", err), "/forgot-password")
		return
	}

	username := sanitizeInput(strings.TrimSpace(r.FormValue("username")))

	if username == "" {
		renderErrorPage(w, http.StatusBadRequest, "Missing Username",
			"Username is required for password reset.",
			"Please provide your username (email or phone number).",
			"Missing username field", "/forgot-password")
		return
	}

	// Validate username format
	var validationErr error
	if isEmail(username) {
		validationErr = validateEmail(username)
	} else if isPhone(username) {
		validationErr = validatePhone(username)
	} else {
		validationErr = fmt.Errorf("username must be a valid email address or phone number")
	}

	if validationErr != nil {
		renderErrorPage(w, http.StatusBadRequest, "Invalid Username Format",
			"The username you provided is not valid.",
			validationErr.Error(),
			validationErr.Error(), "/forgot-password")
		return
	}

	// Check if user exists (but don't reveal if they don't for security)
	info, exists := lookupUserByUsername(username)

	// Generate reset token regardless of user existence (to prevent username enumeration)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		renderErrorPage(w, http.StatusInternalServerError, "System Error",
			"Failed to generate password reset token.",
			"Our system encountered an error. Please try again.",
			fmt.Sprintf("Random token generation failed: %v", err), "/forgot-password")
		return
	}

	token := hex.EncodeToString(tokenBytes)

	// Only set the token if user actually exists
	if exists {
		manager.SetPasswordResetToken(username, token)

		if isEmail(username) {
			sendPasswordResetEmail(username, token)
		} else if isPhone(username) {
			sendPasswordResetSMS(username, token)
		}

		log.Printf("Password reset requested for user: %s (ID: %s)", username, info.UserID)
	}

	// Always show the same success message
	manager.renderTemplate(w, "forgot-password-sent.html", map[string]any{
		"Username": username,
	})
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		token := r.URL.Query().Get("token")
		if token == "" {
			renderErrorPage(w, http.StatusBadRequest, "Missing Reset Token",
				"No password reset token was provided.",
				"Please use the complete reset link from your email or SMS.",
				"Missing token parameter in reset URL", "/forgot-password")
			return
		}

		// Validate token
		resetData, valid := manager.ValidatePasswordResetToken(token)
		if !valid {
			renderErrorPage(w, http.StatusBadRequest, "Invalid or Expired Reset Token",
				"This password reset link is invalid or has expired.",
				"Please request a new password reset link.",
				"Invalid or expired reset token", "/forgot-password")
			return
		}

		manager.renderTemplate(w, "reset-password.html", map[string]any{
			"Token":    token,
			"Username": resetData.Username,
		})
		return
	}

	// POST - Process password reset
	if err := r.ParseForm(); err != nil {
		renderErrorPage(w, http.StatusBadRequest, "Invalid Form Data",
			"The form data could not be processed.",
			"Please check your input and try again.",
			fmt.Sprintf("ParseForm error: %v", err), "/forgot-password")
		return
	}

	token := r.FormValue("token")
	newPassword := r.FormValue("password")
	confirmPassword := r.FormValue("confirmPassword")

	if token == "" || newPassword == "" || confirmPassword == "" {
		renderErrorPage(w, http.StatusBadRequest, "Missing Required Information",
			"All fields are required for password reset.",
			"Please provide the token, new password, and password confirmation.",
			"Missing required fields", "/forgot-password")
		return
	}

	if newPassword != confirmPassword {
		renderErrorPage(w, http.StatusBadRequest, "Password Mismatch",
			"The passwords you entered do not match.",
			"Please ensure both password fields contain the same value.",
			"Password confirmation mismatch", r.URL.Path)
		return
	}

	// Validate new password strength
	if err := validatePassword(newPassword); err != nil {
		renderErrorPage(w, http.StatusBadRequest, "Weak Password",
			"Your new password does not meet the security requirements.",
			err.Error(),
			err.Error(), r.URL.Path)
		return
	}

	// Validate and consume reset token
	resetData, valid := manager.ValidatePasswordResetToken(token)
	if !valid {
		renderErrorPage(w, http.StatusBadRequest, "Invalid or Expired Reset Token",
			"This password reset token is invalid or has expired.",
			"Please request a new password reset link.",
			"Invalid or expired reset token", "/forgot-password")
		return
	}

	if !manager.ConsumePasswordResetToken(token) {
		renderErrorPage(w, http.StatusBadRequest, "Token Already Used",
			"This password reset token has already been used.",
			"Please request a new password reset link if needed.",
			"Reset token already consumed", "/forgot-password")
		return
	}

	// Get user info
	info, exists := lookupUserByUsername(resetData.Username)
	if !exists {
		renderErrorPage(w, http.StatusNotFound, "User Not Found",
			"The user associated with this reset token was not found.",
			"This may indicate a system error. Please try registering again.",
			fmt.Sprintf("User not found for username: %s", resetData.Username), "/register")
		return
	}

	// Hash the new password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		renderErrorPage(w, http.StatusInternalServerError, "Password Processing Error",
			"Failed to securely process your new password.",
			"Our system encountered an error while securing your password. Please try again.",
			fmt.Sprintf("bcrypt hash generation failed: %v", err), "/forgot-password")
		return
	}

	// Update password in database
	if err := manager.Vault.SetUserSecret(info.UserID, string(passwordHash)); err != nil {
		renderErrorPage(w, http.StatusInternalServerError, "Database Error",
			"Failed to update your password in the database.",
			"Our system encountered an error. Please try again.",
			fmt.Sprintf("Database password update failed: %v", err), "/forgot-password")
		return
	}

	// Generate new key pair with new password
	pubx, puby, privd := generateKeyPair()
	newPubHex := padHex(pubx) + ":" + padHex(puby)

	// Update user's public key in the database
	if err := manager.Vault.SetUserPublicKey(info.UserID, padHex(pubx), padHex(puby)); err != nil {
		log.Printf("Failed to update public key for user %s: %v", info.UserID, err)
		// Continue anyway - password was updated successfully
	}

	// Update the pub_hex in users table
	updatedInfo := UserInfo{
		UserID:    info.UserID,
		Username:  info.Username,
		LoginType: info.LoginType,
	}
	if err := manager.Vault.SetUserInfo(newPubHex, updatedInfo); err != nil {
		log.Printf("Failed to update user info with new pub_hex for user %s: %v", info.UserID, err)
	}

	// Register the new key
	manager.RegisterUserKey(newPubHex, []byte(pubx), []byte(puby))

	// Encrypt private key with new password
	encPrivD := encryptPrivateKeyD(privd, newPassword)

	// Prepare new key data for download
	keyData := map[string]string{
		"PubKeyX":              padHex(pubx),
		"PubKeyY":              padHex(puby),
		"EncryptedPrivateKeyD": encPrivD,
	}
	jsonData, _ := json.Marshal(keyData)

	// Encode as base64 for download link
	credentialData := base64.StdEncoding.EncodeToString(jsonData)

	// Generate timestamp for filename
	timestamp := time.Now().Format("20060102_150405")

	log.Printf("Password reset completed for user: %s (ID: %s)", resetData.Username, info.UserID)

	// Render download page with new credentials
	manager.renderTemplate(w, "password-reset-success.html", map[string]any{
		"CredentialData": credentialData,
		"Username":       resetData.Username,
		"Timestamp":      timestamp,
		"GeneratedAt":    time.Now().Format("January 2, 2006 at 3:04 PM"),
	})
}

// --- Registration Handlers ---
func register(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		manager.renderTemplate(w, "register.html", nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderErrorPage(w, http.StatusBadRequest, "Invalid Form Data",
			"The form data you submitted could not be processed.",
			"Please check that all required fields are filled correctly and try again.",
			fmt.Sprintf("ParseForm error: %v", err), "/register")
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirmPassword")
	loginType := r.FormValue("login_type")

	if username == "" || password == "" || confirmPassword == "" {
		renderErrorPage(w, http.StatusBadRequest, "Missing Required Information",
			"Username, password, and password confirmation are required for registration.",
			"Please provide all required fields including password confirmation.",
			"Missing username, password, or confirmPassword fields", "/register")
		return
	}

	// Validate password confirmation
	if password != confirmPassword {
		renderErrorPage(w, http.StatusBadRequest, "Password Mismatch",
			"The passwords you entered do not match.",
			"Please ensure both password fields contain the same value.",
			"Password confirmation mismatch", "/register")
		return
	}

	// Phase 1: Enhanced input validation
	username = sanitizeInput(username)

	// Validate username format
	var validationErr error
	if isEmail(username) {
		validationErr = validateEmail(username)
	} else if isPhone(username) {
		validationErr = validatePhone(username)
	} else {
		validationErr = fmt.Errorf("username must be a valid email address or phone number")
	}

	if validationErr != nil {
		renderErrorPage(w, http.StatusBadRequest, "Invalid Username Format",
			"The username you provided is not valid.",
			validationErr.Error(),
			validationErr.Error(), "/register")
		return
	}

	// Phase 1: Validate password strength
	if err := validatePassword(password); err != nil {
		renderErrorPage(w, http.StatusBadRequest, "Weak Password",
			"Your password does not meet the security requirements.",
			err.Error(),
			err.Error(), "/register")
		return
	}

	// Validate login type
	if loginType != "simple" && loginType != "secured" {
		loginType = "simple" // default to simple
	}

	// Check if username (email/phone) already exists
	if _, exists := lookupUserByUsername(username); exists {
		renderErrorPage(w, http.StatusConflict, "Username Already Registered",
			"This username is already associated with an existing account.",
			"Please try logging in instead, or use a different email address or phone number.",
			fmt.Sprintf("Username '%s' already exists in database", username), "/login")
		return
	}
	// Only store username for now, keys generated after verification
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		renderErrorPage(w, http.StatusInternalServerError, "Registration System Error",
			"Failed to generate verification token.",
			"Our system encountered an error while processing your registration. Please try again.",
			fmt.Sprintf("Random token generation failed: %v", err), "/register")
		return
	}
	token := hex.EncodeToString(tokenBytes)
	manager.SetVerificationToken(username, token)

	// Store login type preference temporarily
	manager.Vault.SetUserSecret(username+"_logintype", loginType)

	// Securely hash password and store in vault for later use
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		renderErrorPage(w, http.StatusInternalServerError, "Password Processing Error",
			"Failed to securely process your password.",
			"Our system encountered an error while securing your password. Please try again.",
			fmt.Sprintf("bcrypt hash generation failed: %v", err), "/register")
		return
	}
	manager.Vault.SetUserSecret(username, string(passwordHash))
	// Store password temporarily for verification step
	manager.Vault.SetUserSecret(username+"_plain", password)
	if isEmail(username) {
		sendVerificationEmail(username, token)
		fmt.Fprintf(w, "Registered. Please check your email for verification.")
	} else if isPhone(username) {
		sendVerificationSMS(username, token)
		fmt.Fprintf(w, "Registered. Please check your phone for verification.")
	} else {
		fmt.Fprintf(w, "Registered. Unknown username type, cannot send verification.")
	}
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	token := r.URL.Query().Get("token")
	if username == "" || token == "" {
		renderErrorPage(w, http.StatusBadRequest, "Invalid Verification Link",
			"The verification link is missing required parameters.",
			"Please check that you clicked the complete link from your email or SMS, or try registering again.",
			"Missing username or token in verification URL", "/register")
		return
	}
	if !manager.VerifyToken(username, token) {
		renderErrorPage(w, http.StatusBadRequest, "Invalid Verification",
			"This verification link is either invalid or has already been used.",
			"The link may have expired or been used already. Please try registering again to get a new verification link.",
			"Verification token does not match or does not exist", "/register")
		return
	}

	// Get login type preference
	loginType, err := manager.Vault.GetUserSecret(username + "_logintype")
	if err != nil {
		loginType = "simple" // default to simple
	}
	manager.Vault.SetUserSecret(username+"_logintype", "") // Remove temp

	// Generate key pair after verification
	pubx, puby, privd := generateKeyPair()
	pubHex := padHex(pubx) + ":" + padHex(puby)
	info := UserInfo{
		UserID:    wuid.New().String(),
		Username:  username,
		LoginType: loginType,
	}
	manager.Vault.SetUserInfo(pubHex, info)
	// Store public key in credentials table
	manager.Vault.SetUserPublicKey(info.UserID, padHex(pubx), padHex(puby))
	manager.RegisterUserKey(pubHex, []byte(pubx), []byte(puby))
	// Retrieve password hash and move to DBUserID key
	passwordHash, err := manager.Vault.GetUserSecret(username)
	if err == nil {
		manager.Vault.SetUserSecret(info.UserID, passwordHash)
		manager.Vault.SetUserSecret(username, "") // Remove temp
	}
	// Retrieve plaintext password for encryption
	password, err := manager.Vault.GetUserSecret(username + "_plain")
	manager.Vault.SetUserSecret(username+"_plain", "") // Remove temp
	if err != nil || password == "" {
		renderErrorPage(w, http.StatusInternalServerError, "Account Setup Error",
			"Failed to complete account setup due to missing password information.",
			"There was an issue finalizing your account. Please try registering again.",
			"Password not found for key encryption during verification", "/register")
		return
	}
	encPrivD := encryptPrivateKeyD(privd, password)
	keyData := map[string]string{
		"PubKeyX":              padHex(pubx),
		"PubKeyY":              padHex(puby),
		"EncryptedPrivateKeyD": encPrivD,
	}
	jsonData, _ := json.Marshal(keyData)
	manager.renderTemplate(w, "download-key-file.html", map[string]any{"KeyJson": template.JS(string(jsonData))})
}
