package pkg

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/oarkflow/paseto/token"
	"golang.org/x/crypto/bcrypt"
)

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

	if userInfo.MFAEnabled {
		manager.renderTemplate(w, "mfa-verify.html", map[string]interface{}{
			"Username": username,
		})
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

		// Check if MFA is enabled for this user
		mfaEnabled, err := manager.Vault.IsUserMFAEnabled(info.UserID)
		if err == nil && mfaEnabled {
			// Store login state temporarily for MFA verification
			setSessionData(w, "login_username", username)
			setSessionData(w, "login_client_id", clientID)
			setSessionData(w, "login_redirect_uri", redirectURI)
			setSessionData(w, "login_scope", scope)
			setSessionData(w, "login_state", state)

			// Redirect to MFA verification
			manager.renderTemplate(w, "mfa-verify.html", map[string]interface{}{
				"Username": username,
			})
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
