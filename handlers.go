package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func LogoutHandler(auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractSessionToken(r)
		if token == "" {
			writeError(w, "missing session token", http.StatusUnauthorized)
			return
		}
		if err := auth.Sessions.Revoke(r.Context(), token); err != nil {
			writeError(w, "logout failed", http.StatusInternalServerError)
			return
		}
		// Clear session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- Frontend HTTP Handlers for Password Management ---

// Serve static HTML pages for endpoints
func ServeHTMLPage(page string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := LoadTemplate(page)
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		_ = tmpl.Execute(w, map[string]interface{}{})
	}
}

func FrontendForgotPasswordHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{}
		tmpl, err := LoadTemplate("forgot")
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		if r.Method == http.MethodPost {
			email := r.FormValue("email")
			if email == "" {
				data["Error"] = "Email required"
				_ = tmpl.Execute(w, data)
				return
			}
			var userID string
			row := db.QueryRow(`SELECT id FROM users WHERE email=?`, email)
			if err := row.Scan(&userID); err != nil {
				data["Error"] = "User not found"
				_ = tmpl.Execute(w, data)
				return
			}
			token, hash := generateResetToken()
			_, err := db.Exec(`INSERT INTO password_resets(user_id, token_hash, expires_at, used) VALUES(?,?,?,0)`,
				userID, hash, time.Now().Add(30*time.Minute))
			if err != nil {
				data["Error"] = "Could not create reset token"
				_ = tmpl.Execute(w, data)
				return
			}
			// In production, send token via email. Here, just show it.
			data["ResetToken"] = token
		}
		_ = tmpl.Execute(w, data)
	}
}

func FrontendResetPasswordHandler(db *sql.DB, auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{}
		tmpl, err := LoadTemplate("reset")
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		if r.Method == http.MethodPost {
			token := r.FormValue("token")
			password := r.FormValue("password")
			if token == "" || password == "" {
				data["Error"] = "Token and new password required"
				_ = tmpl.Execute(w, data)
				return
			}
			if err := validatePasswordPolicy(password); err != nil {
				data["Error"] = err.Error()
				_ = tmpl.Execute(w, data)
				return
			}
			hash := sha256.Sum256([]byte(token))
			var userID string
			var expires time.Time
			var used int
			row := db.QueryRow(`SELECT user_id, expires_at, used FROM password_resets WHERE token_hash=?`, base64.StdEncoding.EncodeToString(hash[:]))
			if err := row.Scan(&userID, &expires, &used); err != nil || used != 0 || time.Now().After(expires) {
				data["Error"] = "Invalid or expired token"
				_ = tmpl.Execute(w, data)
				return
			}
			passHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			reused, _ := checkPasswordReuse(db, userID, string(passHash))
			if reused {
				data["Error"] = "Cannot reuse previous passwords"
				_ = tmpl.Execute(w, data)
				return
			}
			_, err := db.Exec(`UPDATE credentials SET secret_hash=? WHERE user_id=? AND type='password'`, string(passHash), userID)
			if err != nil {
				data["Error"] = "Could not update password"
				_ = tmpl.Execute(w, data)
				return
			}
			_, _ = db.Exec(`UPDATE password_resets SET used=1 WHERE token_hash=?`, base64.StdEncoding.EncodeToString(hash[:]))
			_ = auth.Sessions.RevokeAllForUser(r.Context(), userID)
			_ = storePasswordHistory(db, userID, string(passHash))
			data["Success"] = true
		}
		_ = tmpl.Execute(w, data)
	}
}

func FrontendChangePasswordHandler(db *sql.DB, auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{}
		tmpl, err := LoadTemplate("change")
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		var sessionToken string
		// Try to get session token from cookie
		if cookie, err := r.Cookie("session_token"); err == nil {
			sessionToken = cookie.Value
		}
		if r.Method == http.MethodPost {
			if sessionToken == "" {
				sessionToken = r.FormValue("session_token")
			}
			oldPassword := r.FormValue("old_password")
			newPassword := r.FormValue("new_password")
			if sessionToken == "" || oldPassword == "" || newPassword == "" {
				data["Error"] = "All fields required"
				_ = tmpl.Execute(w, data)
				return
			}
			if err := validatePasswordPolicy(newPassword); err != nil {
				data["Error"] = err.Error()
				_ = tmpl.Execute(w, data)
				return
			}
			sess, err := auth.Sessions.Validate(r.Context(), sessionToken)
			if err != nil {
				data["Error"] = "Invalid session"
				_ = tmpl.Execute(w, data)
				return
			}
			var secretHash string
			row := db.QueryRow(`SELECT secret_hash FROM credentials WHERE user_id=? AND type='password'`, sess.UserID)
			if err := row.Scan(&secretHash); err != nil {
				data["Error"] = "User not found"
				_ = tmpl.Execute(w, data)
				return
			}
			if err := bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(oldPassword)); err != nil {
				data["Error"] = "Old password incorrect"
				_ = tmpl.Execute(w, data)
				return
			}
			passHash, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			_, err = db.Exec(`UPDATE credentials SET secret_hash=? WHERE user_id=? AND type='password'`, string(passHash), sess.UserID)
			if err != nil {
				data["Error"] = "Could not update password"
				_ = tmpl.Execute(w, data)
				return
			}
			_ = auth.Sessions.RevokeAllForUser(r.Context(), sess.UserID)
			// Clear session cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})
			data["Success"] = true
		}
		_ = tmpl.Execute(w, data)
	}
}

// --- Update FrontendHandler to set session cookie on login and clear on logout ---

func FrontendHandler(auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{}
		tmpl, err := LoadTemplate("login")
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		// Pass CSRF token to template
		if token, ok := r.Context().Value("csrf_token").(string); ok {
			data["CSRFToken"] = token
		} else if cookie, err := r.Cookie("csrf_token"); err == nil {
			data["CSRFToken"] = cookie.Value
		}
		if r.Method == http.MethodPost {
			method := r.FormValue("method")
			var identifier, secret string
			switch method {
			case "password":
				identifier = r.FormValue("username")
				secret = r.FormValue("password")
			case "apikey":
				identifier = "k1"
				secret = r.FormValue("apikey")
			case "cognito", "oauth2", "google", "clerk":
				identifier = r.FormValue("username")
				secret = r.FormValue("token")
			case "totp":
				identifier = r.FormValue("username")
				secret = r.FormValue("totp")
			case "mfa", "2fa":
				identifier = r.FormValue("username")
				secret = r.FormValue("mfa")
			default:
				data["Error"] = "Unsupported method"
				_ = tmpl.Execute(w, data)
				return
			}
			res, err := auth.Authenticate(r.Context(), AuthRequest{
				Method:     method,
				Identifier: identifier,
				Secret:     secret,
				RemoteIP:   r.RemoteAddr,
				UserAgent:  r.UserAgent(),
			})
			if err != nil {
				data["Error"] = err.Error()
			} else {
				data["Token"] = res.Token
				// Split by '|'
				toks := strings.SplitN(res.Token, "|", 2)
				if len(toks) == 2 {
					data["SessionToken"] = toks[1]
					setSessionCookie(w, toks[1])
				}
			}
		}
		_ = tmpl.Execute(w, data)
	}
}

// --- User Registration & Email Verification ---

func RegisterHandler(db *sql.DB, sendEmail func(to, subject, html string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		if username == "" || email == "" || password == "" {
			writeError(w, "missing fields", http.StatusBadRequest)
			return
		}
		if err := validatePasswordPolicy(password); err != nil {
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		passHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		userID := generateUserID(username)
		_, err := db.Exec(`INSERT INTO users(id, username, email, email_verified, created_at, updated_at) VALUES(?,?,?,?,?,?)`,
			userID, username, email, 0, time.Now(), time.Now())
		if err != nil {
			writeError(w, "user exists", http.StatusConflict)
			return
		}
		_, err = db.Exec(`INSERT INTO credentials(id, user_id, type, provider, identifier, secret_hash, created_at)
			VALUES(?,?,?,?,?,?,?)`,
			"c-"+userID, userID, "password", "internal", username, string(passHash), time.Now())
		if err != nil {
			writeError(w, "credential error", http.StatusInternalServerError)
			return
		}
		// Email verification token
		token, hash := generateResetToken()
		_, _ = db.Exec(`INSERT INTO email_verifications(user_id, token_hash, expires_at, used) VALUES(?,?,?,0)`,
			userID, hash, time.Now().Add(24*time.Hour))
		// Send email (stub)
		_ = sendEmail(email, "Verify your account", fmt.Sprintf("Click to verify: https://yourdomain/verify-email?token=%s", token))
		w.WriteHeader(http.StatusCreated)
	}
}

func VerifyEmailHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			writeError(w, "missing token", http.StatusBadRequest)
			return
		}
		hash := sha256.Sum256([]byte(token))
		var userID string
		var expires time.Time
		var used int
		row := db.QueryRow(`SELECT user_id, expires_at, used FROM email_verifications WHERE token_hash=?`, base64.StdEncoding.EncodeToString(hash[:]))
		if err := row.Scan(&userID, &expires, &used); err != nil || used != 0 || time.Now().After(expires) {
			writeError(w, "invalid or expired token", http.StatusBadRequest)
			return
		}
		_ = markEmailVerified(db, userID)
		_, _ = db.Exec(`UPDATE email_verifications SET used=1 WHERE token_hash=?`, base64.StdEncoding.EncodeToString(hash[:]))
		w.Write([]byte("Email verified!"))
	}
}

// --- MFA Enrollment (TOTP) ---

func EnrollTOTPHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.FormValue("user_id")
		if userID == "" {
			writeError(w, "missing user_id", http.StatusBadRequest)
			return
		}
		secret := generateTOTPSecret() // stub, use otp.NewKey()
		_ = enrollTOTP(db, userID, secret)
		// Show QR code or secret to user (not implemented here)
		w.Write([]byte(fmt.Sprintf("TOTP secret: %s", secret)))
	}
}

// --- Session Concurrency & Device Management ---

func ListSessionsHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.FormValue("user_id")
		rows, err := db.Query(`SELECT id, user_agent, ip, created_at, expires_at, revoked FROM sessions WHERE user_id=?`, userID)
		if err != nil {
			writeError(w, "db error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var sessions []map[string]interface{}
		for rows.Next() {
			var id, ua, ip string
			var created, expires time.Time
			var revoked int
			_ = rows.Scan(&id, &ua, &ip, &created, &expires, &revoked)
			sessions = append(sessions, map[string]interface{}{
				"id": id, "user_agent": ua, "ip": ip, "created_at": created, "expires_at": expires, "revoked": revoked != 0,
			})
		}
		_ = json.NewEncoder(w).Encode(sessions)
	}
}

func RevokeSessionHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.FormValue("session_id")
		_, err := db.Exec(`UPDATE sessions SET revoked=1 WHERE id=?`, sessionID)
		if err != nil {
			writeError(w, "db error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- HTTP Handler ---

func AuthHandler(auth *Authenticator, auditor *AuditLogger, limiter *rateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Secure headers
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "X-Auth-Method, X-Auth-Credential, X-Auth-Provider, Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		if !limiter.Allow(ip) {
			auditor.LogEvent("rate_limited", zap.String("ip", ip))
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		method := r.Header.Get("X-Auth-Method")
		identifier := r.Header.Get("X-Auth-Identifier")
		secret := r.Header.Get("X-Auth-Secret")
		if method == "" || identifier == "" || secret == "" {
			writeError(w, "missing auth method, identifier or secret", http.StatusBadRequest)
			return
		}
		res, err := auth.Authenticate(r.Context(), AuthRequest{
			Method:     method,
			Identifier: identifier,
			Secret:     secret,
			RemoteIP:   ip,
			UserAgent:  r.UserAgent(),
		})
		if err != nil {
			auditor.LogEvent("auth_failed", zap.String("reason", err.Error()), zap.String("ip", ip))
			writeError(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	}
}

// --- Refresh Token Endpoint Example ---

func RefreshTokenHandler(auth *Authenticator, db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refresh := r.FormValue("refresh_token")
		if refresh == "" {
			writeError(w, "missing refresh token", http.StatusBadRequest)
			return
		}
		userID, err := validateRefreshToken(db, refresh)
		if err != nil {
			writeError(w, "invalid refresh token", http.StatusUnauthorized)
			return
		}
		token, err := auth.Signer.Sign(userID)
		if err != nil {
			writeError(w, "token error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
}

// Add endpoints to serve HTML pages
func RegisterHTMLRoutes() {
	http.Handle("/login.html", ServeHTMLPage("login"))
	http.Handle("/forgot-password.html", ServeHTMLPage("forgot"))
	http.Handle("/reset-password.html", ServeHTMLPage("reset"))
	http.Handle("/change-password.html", ServeHTMLPage("change"))
	// Add more as needed
}

// --- Simple Login and Secured Login Handlers ---

// Login selection handler
func LoginSelectionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		data := map[string]interface{}{
			"HasUser": false,
		}

		if username != "" {
			// Look up user to show their preferred login type
			// This is optional for display purposes
			data["Username"] = username
			data["HasUser"] = true
		}

		tmpl, err := LoadTemplate("login-selection")
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		_ = tmpl.Execute(w, data)
	}
}

// Simple Login Handler - supports all external providers
func SimpleLoginHandler(db *sql.DB, auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{
			"CSRFToken": r.Context().Value("csrf_token"),
		}

		if r.Method == http.MethodGet {
			tmpl, err := LoadTemplate("simple-login")
			if err != nil {
				http.Error(w, "template error", http.StatusInternalServerError)
				return
			}
			_ = tmpl.Execute(w, data)
			return
		}

		// Handle POST request
		if err := r.ParseForm(); err != nil {
			data["Error"] = "Invalid form data"
			tmpl, _ := LoadTemplate("simple-login")
			_ = tmpl.Execute(w, data)
			return
		}

		provider := r.FormValue("provider")
		identifier := strings.TrimSpace(r.FormValue("identifier"))
		secret := r.FormValue("secret")

		if provider == "" || identifier == "" || secret == "" {
			data["Error"] = "All fields are required"
			tmpl, _ := LoadTemplate("simple-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Check if user exists and if they're allowed to use simple login
		var userID, storedLoginType string
		err := db.QueryRow(`SELECT id, COALESCE(login_type, 'simple') FROM users WHERE username = ? OR email = ?`,
			identifier, identifier).Scan(&userID, &storedLoginType)

		if err == nil && storedLoginType == "secured" {
			data["Error"] = "Your account requires secured login with cryptographic key file"
			tmpl, _ := LoadTemplate("simple-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Authenticate using the provider
		authReq := AuthRequest{
			Method:     provider,
			Identifier: identifier,
			Secret:     secret,
			RemoteIP:   getClientIP(r),
			UserAgent:  r.UserAgent(),
		}

		result, err := auth.Authenticate(r.Context(), authReq)
		if err != nil {
			data["Error"] = "Authentication failed: " + err.Error()
			tmpl, _ := LoadTemplate("simple-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Create session
		session, err := auth.Sessions.Create(r.Context(), result.UserID, r.UserAgent(), getClientIP(r), 24*time.Hour)
		if err != nil {
			data["Error"] = "Failed to create session"
			tmpl, _ := LoadTemplate("simple-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Set session cookie
		setSessionCookie(w, session.Token)

		// Redirect to protected area
		http.Redirect(w, r, "/protected", http.StatusSeeOther)
	}
}

// Secured Login Handler - requires encrypted JSON key file + provider authentication
func SecuredLoginHandler(db *sql.DB, auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{
			"CSRFToken": r.Context().Value("csrf_token"),
		}

		if r.Method == http.MethodGet {
			tmpl, err := LoadTemplate("secured-login")
			if err != nil {
				http.Error(w, "template error", http.StatusInternalServerError)
				return
			}
			_ = tmpl.Execute(w, data)
			return
		}

		// Handle POST request
		if err := r.ParseMultipartForm(1 << 20); err != nil { // 1MB max
			data["Error"] = "Failed to parse form data"
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Get form values
		provider := r.FormValue("provider")
		identifier := strings.TrimSpace(r.FormValue("identifier"))
		secret := r.FormValue("secret")
		keyPassword := r.FormValue("key_password")

		if provider == "" || identifier == "" || secret == "" || keyPassword == "" {
			data["Error"] = "All fields are required"
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Get uploaded key file
		file, _, err := r.FormFile("keyfile")
		if err != nil {
			data["Error"] = "Cryptographic key file is required"
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}
		defer file.Close()

		// Parse key file
		var keyData map[string]string
		if err := json.NewDecoder(file).Decode(&keyData); err != nil {
			data["Error"] = "Invalid key file format"
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Validate key file structure
		publicKeyX, ok1 := keyData["PubKeyX"]
		publicKeyY, ok2 := keyData["PubKeyY"]
		encryptedPrivateKey, ok3 := keyData["EncryptedPrivateKeyD"]

		if !ok1 || !ok2 || !ok3 {
			data["Error"] = "Key file is missing required cryptographic data"
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Find user by public key
		var userID string
		err = db.QueryRow(`
			SELECT user_id FROM user_crypto_keys
			WHERE public_key_x = ? AND public_key_y = ?
		`, publicKeyX, publicKeyY).Scan(&userID)

		if err != nil {
			data["Error"] = "Unrecognized cryptographic key"
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Verify user exists and uses secured login
		var username, storedLoginType string
		err = db.QueryRow(`SELECT username, COALESCE(login_type, 'simple') FROM users WHERE id = ?`,
			userID).Scan(&username, &storedLoginType)

		if err != nil {
			data["Error"] = "User account not found"
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Decrypt private key to verify key file password
		privateKeyD, err := decryptPrivateKeyWithPassword(encryptedPrivateKey, keyPassword)
		if err != nil {
			data["Error"] = "Failed to decrypt private key - incorrect key file password"
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Generate cryptographic proof
		nonce, err := generateRandomString(32)
		if err != nil {
			data["Error"] = "Failed to generate nonce"
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}
		timestamp := time.Now().Unix()

		proof, err := generateCryptographicProof(privateKeyD, nonce, timestamp)
		if err != nil {
			data["Error"] = "Failed to generate cryptographic proof"
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Verify the proof
		if err := verifyCryptographicProof(proof, publicKeyX, publicKeyY); err != nil {
			data["Error"] = "Cryptographic proof verification failed"
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Now authenticate with the provider
		authReq := AuthRequest{
			Method:     provider,
			Identifier: identifier,
			Secret:     secret,
			RemoteIP:   getClientIP(r),
			UserAgent:  r.UserAgent(),
		}

		result, err := auth.Authenticate(r.Context(), authReq)
		if err != nil {
			data["Error"] = "Provider authentication failed: " + err.Error()
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Verify that the authenticated user matches the key file user
		if result.UserID != userID {
			data["Error"] = "Key file does not match the authenticated user"
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Create session
		session, err := auth.Sessions.Create(r.Context(), result.UserID, r.UserAgent(), getClientIP(r), 24*time.Hour)
		if err != nil {
			data["Error"] = "Failed to create session"
			tmpl, _ := LoadTemplate("secured-login")
			_ = tmpl.Execute(w, data)
			return
		}

		// Set session cookie
		setSessionCookie(w, session.Token)

		// Audit log the secured login
		auth.Auditor.LogEvent("secured_login",
			zap.String("user_id", userID),
			zap.String("username", username),
			zap.String("provider", provider),
			zap.String("ip", getClientIP(r)),
		)

		// Redirect to protected area
		http.Redirect(w, r, "/protected", http.StatusSeeOther)
	}
}

// Helper function to get client IP
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Get first IP in case of multiple
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Enhanced User Registration Handler with Login Type Selection
func EnhancedRegisterHandler(db *sql.DB, sendEmail func(to, subject, html string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{
			"CSRFToken": r.Context().Value("csrf_token"),
		}

		tmpl, err := LoadTemplate("register")
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}

		if r.Method == http.MethodGet {
			_ = tmpl.Execute(w, data)
			return
		}

		// Handle POST request
		if err := r.ParseForm(); err != nil {
			data["Error"] = "Invalid form data"
			_ = tmpl.Execute(w, data)
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		email := strings.TrimSpace(r.FormValue("email"))
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")
		loginType := r.FormValue("login_type") // "simple" or "secured"

		if username == "" || email == "" || password == "" || confirmPassword == "" {
			data["Error"] = "All fields are required"
			_ = tmpl.Execute(w, data)
			return
		}

		if password != confirmPassword {
			data["Error"] = "Passwords do not match"
			_ = tmpl.Execute(w, data)
			return
		}

		if loginType == "" {
			loginType = "simple" // Default to simple login
		}

		if err := validatePasswordPolicy(password); err != nil {
			data["Error"] = err.Error()
			_ = tmpl.Execute(w, data)
			return
		}

		// Check if user already exists
		var existingUser string
		err = db.QueryRow(`SELECT id FROM users WHERE username = ? OR email = ?`, username, email).Scan(&existingUser)
		if err == nil {
			data["Error"] = "User with this username or email already exists"
			_ = tmpl.Execute(w, data)
			return
		}

		// Hash password
		passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			data["Error"] = "Failed to process password"
			_ = tmpl.Execute(w, data)
			return
		}

		// Generate user ID
		userID := generateUserID(username)

		// Create user
		_, err = db.Exec(`INSERT INTO users(id, username, email, email_verified, login_type, created_at, updated_at) VALUES(?,?,?,?,?,?,?)`,
			userID, username, email, 0, loginType, time.Now(), time.Now())
		if err != nil {
			data["Error"] = "Failed to create user account"
			_ = tmpl.Execute(w, data)
			return
		}

		// Create password credential
		_, err = db.Exec(`INSERT INTO credentials(id, user_id, type, provider, identifier, secret_hash, created_at)
			VALUES(?,?,?,?,?,?,?)`,
			"c-"+userID, userID, "password", "internal", username, string(passHash), time.Now())
		if err != nil {
			data["Error"] = "Failed to create credentials"
			_ = tmpl.Execute(w, data)
			return
		}

		// If secured login, generate cryptographic keys
		var keyFileData map[string]string
		if loginType == "secured" {
			// Generate ECDSA key pair
			rsaKey, publicKeyX, publicKeyY, err := generateECDSAKeyPair()
			if err != nil {
				data["Error"] = "Failed to generate cryptographic keys"
				_ = tmpl.Execute(w, data)
				return
			}

			// Use the RSA private key D value as the private key for compatibility
			privateKeyD := rsaKey.D.String()

			// Encrypt private key with user's password
			encryptedPrivateKey, err := encryptPrivateKeyWithPassword(privateKeyD, password)
			if err != nil {
				data["Error"] = "Failed to encrypt private key"
				_ = tmpl.Execute(w, data)
				return
			}

			// Store cryptographic keys
			err = storeUserCryptographicKeys(db, userID, publicKeyX, publicKeyY, encryptedPrivateKey)
			if err != nil {
				data["Error"] = "Failed to store cryptographic keys"
				_ = tmpl.Execute(w, data)
				return
			}

			// Prepare key file data for download
			keyFileData = map[string]string{
				"PubKeyX":              publicKeyX,
				"PubKeyY":              publicKeyY,
				"EncryptedPrivateKeyD": encryptedPrivateKey,
				"UserID":               userID,
				"Username":             username,
				"LoginType":            loginType,
			}
		}

		// Email verification token
		token, hash := generateResetToken()
		_, _ = db.Exec(`INSERT INTO email_verifications(user_id, token_hash, expires_at, used) VALUES(?,?,?,0)`,
			userID, hash, time.Now().Add(24*time.Hour))

		// Send email (stub)
		_ = sendEmail(email, "Verify your account", fmt.Sprintf("Click to verify: https://yourdomain/verify-email?token=%s", token))

		// Registration success data
		data["Success"] = true
		data["Username"] = username
		data["LoginType"] = loginType
		data["VerificationToken"] = token // For demo purposes - remove in production

		if loginType == "secured" {
			// Convert key file data to JSON for download
			keyFileJSON, _ := json.MarshalIndent(keyFileData, "", "  ")
			data["KeyFile"] = string(keyFileJSON)
			data["KeyFileName"] = fmt.Sprintf("%s_crypto_key.json", username)
		}

		_ = tmpl.Execute(w, data)
	}
}

// Protected Page Handler - demonstrates successful authentication
func ProtectedHandler(db *sql.DB, auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for session token
		token := extractSessionToken(r)
		if token == "" {
			http.Redirect(w, r, "/login-selection", http.StatusSeeOther)
			return
		}

		// Validate session
		session, err := auth.Sessions.Validate(r.Context(), token)
		if err != nil {
			http.Redirect(w, r, "/login-selection", http.StatusSeeOther)
			return
		}

		// Get user information
		var username, email, loginType string
		err = db.QueryRow(`SELECT username, email, COALESCE(login_type, 'simple') FROM users WHERE id = ?`,
			session.UserID).Scan(&username, &email, &loginType)
		if err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}

		// Prepare template data
		data := map[string]interface{}{
			"UserID":      session.UserID,
			"Username":    username,
			"Email":       email,
			"LoginMethod": loginType,
			"IP":          getClientIP(r),
			"UserAgent":   r.UserAgent(),
			"LoginTime":   session.CreatedAt.Format("2006-01-02 15:04:05"),
		}

		tmpl, err := LoadTemplate("protected")
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		_ = tmpl.Execute(w, data)
	}
}

// Home Handler
func HomeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := LoadTemplate("index")
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		_ = tmpl.Execute(w, map[string]interface{}{})
	}
}

// SSO Handler - Single Sign-On with token
func SSOHandler(auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Get("token") == "" {
			// Show SSO page
			tmpl, err := LoadTemplate("sso")
			if err != nil {
				http.Error(w, "template error", http.StatusInternalServerError)
				return
			}
			_ = tmpl.Execute(w, map[string]interface{}{})
			return
		}

		if r.Method == http.MethodPost {
			// Handle SSO login form
			username := strings.TrimSpace(r.FormValue("username"))
			password := r.FormValue("password")

			if username == "" || password == "" {
				http.Error(w, "username and password required", http.StatusBadRequest)
				return
			}

			// Authenticate user
			authReq := AuthRequest{
				Method:     "password",
				Identifier: username,
				Secret:     password,
				RemoteIP:   getClientIP(r),
				UserAgent:  r.UserAgent(),
			}

			result, err := auth.Authenticate(r.Context(), authReq)
			if err != nil {
				http.Error(w, "authentication failed", http.StatusUnauthorized)
				return
			}

			// Create session
			session, err := auth.Sessions.Create(r.Context(), result.UserID, r.UserAgent(), getClientIP(r), 24*time.Hour)
			if err != nil {
				http.Error(w, "failed to create session", http.StatusInternalServerError)
				return
			}

			// Generate SSO link with token
			ssoLink := fmt.Sprintf("https://%s/sso?token=%s", r.Host, session.Token)

			// Show SSO link page
			tmpl, err := LoadTemplate("sso-link")
			if err != nil {
				http.Error(w, "template error", http.StatusInternalServerError)
				return
			}
			_ = tmpl.Execute(w, map[string]interface{}{
				"SSOLink":  ssoLink,
				"Username": username,
			})
			return
		}

		// GET with token in URL - SSO login
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}

		// Validate session token
		_, err := auth.Sessions.Validate(r.Context(), token)
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Set session cookie and redirect
		setSessionCookie(w, token)
		http.Redirect(w, r, "/protected", http.StatusSeeOther)
	}
}

// Nonce Handler - Generate cryptographic nonce
func NonceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := generateRandomString(32)
		if err != nil {
			writeError(w, "failed to generate nonce", http.StatusInternalServerError)
			return
		}

		timestamp := time.Now().Unix()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"nonce":     nonce,
			"timestamp": timestamp,
		})
	}
}

// API Status Handler
func APIStatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "online",
			"version":   "1.0.0",
			"features":  []string{"simple-login", "secured-login", "multi-provider", "sessions", "mfa"},
			"timestamp": time.Now().Unix(),
		})
	}
}

// API User Info Handler - Get current user information
func APIUserInfoHandler(db *sql.DB, auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract token from cookie or Authorization header
		token := extractSessionToken(r)
		if token == "" {
			writeError(w, "no authentication token provided", http.StatusUnauthorized)
			return
		}

		// Validate session
		session, err := auth.Sessions.Validate(r.Context(), token)
		if err != nil {
			writeError(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// Get user information
		var username, email, loginType string
		err = db.QueryRow(`SELECT username, email, COALESCE(login_type, 'simple') FROM users WHERE id = ?`,
			session.UserID).Scan(&username, &email, &loginType)
		if err != nil {
			writeError(w, "user not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": true,
			"user": map[string]interface{}{
				"id":        session.UserID,
				"username":  username,
				"email":     email,
				"loginType": loginType,
			},
			"session": map[string]interface{}{
				"createdAt": session.CreatedAt,
				"expiresAt": session.ExpiresAt,
			},
		})
	}
}

// API Simple Login Handler - for API/AJAX requests
func APISimpleLoginHandler(db *sql.DB, auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var loginData struct {
			Provider   string `json:"provider"`
			Identifier string `json:"identifier"`
			Secret     string `json:"secret"`
		}

		if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
			writeError(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		if loginData.Provider == "" || loginData.Identifier == "" || loginData.Secret == "" {
			writeError(w, "all fields required", http.StatusBadRequest)
			return
		}

		// Check if user exists and login type
		var userID, storedLoginType string
		err := db.QueryRow(`SELECT id, COALESCE(login_type, 'simple') FROM users WHERE username = ? OR email = ?`,
			loginData.Identifier, loginData.Identifier).Scan(&userID, &storedLoginType)

		if err == nil && storedLoginType == "secured" {
			writeError(w, "account requires secured login", http.StatusForbidden)
			return
		}

		// Authenticate
		authReq := AuthRequest{
			Method:     loginData.Provider,
			Identifier: loginData.Identifier,
			Secret:     loginData.Secret,
			RemoteIP:   getClientIP(r),
			UserAgent:  r.UserAgent(),
		}

		result, err := auth.Authenticate(r.Context(), authReq)
		if err != nil {
			writeError(w, "authentication failed", http.StatusUnauthorized)
			return
		}

		// Create session
		session, err := auth.Sessions.Create(r.Context(), result.UserID, r.UserAgent(), getClientIP(r), 24*time.Hour)
		if err != nil {
			writeError(w, "failed to create session", http.StatusInternalServerError)
			return
		}

		// Set session cookie
		setSessionCookie(w, session.Token)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"token":      session.Token,
			"user_id":    result.UserID,
			"expires_at": session.ExpiresAt,
		})
	}
}

// Enhanced Logout Handler with session blacklist
var logoutBlacklist = make(map[string]int64)
var logoutBlacklistMu sync.Mutex

func EnhancedLogoutHandler(auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			tmpl, err := LoadTemplate("logout")
			if err != nil {
				http.Error(w, "template error", http.StatusInternalServerError)
				return
			}
			_ = tmpl.Execute(w, map[string]interface{}{})
			return
		}

		token := extractSessionToken(r)
		if token == "" {
			writeError(w, "missing session token", http.StatusUnauthorized)
			return
		}

		// Validate and get session info
		session, err := auth.Sessions.Validate(r.Context(), token)
		if err != nil {
			writeError(w, "invalid session", http.StatusUnauthorized)
			return
		}

		// Revoke session
		if err := auth.Sessions.Revoke(r.Context(), token); err != nil {
			writeError(w, "logout failed", http.StatusInternalServerError)
			return
		}

		// Add to blacklist to prevent reuse
		logoutBlacklistMu.Lock()
		now := time.Now().Unix()
		// Clean up old entries
		for k, exp := range logoutBlacklist {
			if exp < now {
				delete(logoutBlacklist, k)
			}
		}
		logoutBlacklist[token] = session.ExpiresAt.Unix()
		logoutBlacklistMu.Unlock()

		// Clear session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		// Audit log
		auth.Auditor.LogEvent("logout",
			zap.String("user_id", session.UserID),
			zap.String("ip", getClientIP(r)),
		)

		// Redirect to home
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// Session validation middleware
func SessionValidationMiddleware(auth *Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractSessionToken(r)
			if token != "" {
				// Check blacklist
				logoutBlacklistMu.Lock()
				exp, blacklisted := logoutBlacklist[token]
				logoutBlacklistMu.Unlock()

				if blacklisted && exp > time.Now().Unix() {
					http.Error(w, "session invalidated", http.StatusUnauthorized)
					return
				}

				// Validate session
				session, err := auth.Sessions.Validate(r.Context(), token)
				if err == nil {
					// Add user info to context
					ctx := context.WithValue(r.Context(), "user_id", session.UserID)
					ctx = context.WithValue(ctx, "session", session)
					r = r.WithContext(ctx)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
