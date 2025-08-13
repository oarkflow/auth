package pkg

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/oarkflow/paseto/token"
	"github.com/oarkflow/xid/wuid"
	"golang.org/x/crypto/bcrypt"
)

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

		// Get MFA status
		mfaEnabled, _ := manager.Vault.IsUserMFAEnabled(info.UserID)

		iat, _ := claims["iat"].(float64)
		exp_claim, _ := claims["exp"].(float64)

		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"user": map[string]any{
				"id":          info.UserID,
				"username":    info.Username,
				"login_type":  info.LoginType,
				"mfa_enabled": mfaEnabled,
				"pubKeyX":     pubKeyX,
				"pubKeyY":     pubKeyY,
				"pubHex":      pubHex,
			},
			"session": map[string]any{
				"issuedAt":  int64(iat),
				"expiresAt": int64(exp_claim),
				"timeLeft":  int64(exp_claim) - time.Now().Unix(),
			},
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
	fmt.Println(loginType)
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
	if loginType == "simple" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
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
