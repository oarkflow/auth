package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Global constants
const (
	expDuration     = 15 * time.Minute
	nonceCleanupSec = 60
	// Phase 1 Security Constants
	maxLoginAttempts    = 5
	loginCooldownPeriod = 15 * time.Minute
	maxRequestsPerMin   = 30
	passwordMinLength   = 8
	// Password Reset Constants
	passwordResetTokenExp = 30 * time.Minute
)

// Phase 1: Rate Limiting and Security Structures
type RateLimiter struct {
	requests map[string][]time.Time
	attempts map[string][]time.Time
	mu       sync.RWMutex
}

// --- Types ---
type UserInfo struct {
	UserID    string `db:"user_id"`
	Username  string `db:"username"`
	LoginType string `db:"login_type"`
}

type schnorrProof struct {
	R       string `json:"R"`
	S       string `json:"S"`
	PubKeyX string `json:"pubKeyX"`
	PubKeyY string `json:"pubKeyY"`
	Nonce   string `json:"nonce"`
	Ts      int64  `json:"ts"`
}

type ErrorPageData struct {
	Title       string
	StatusCode  int
	Message     string
	Description string
	Technical   string
	RetryURL    string
	ErrorID     string
}

type PasswordResetData struct {
	Username  string
	Token     string
	ExpiresAt time.Time
	Used      bool
}

// Detect if username is email or phone
func isEmail(username string) bool {
	re := regexp.MustCompile(`^[^@]+@[^@]+\.[^@]+$`)
	return re.MatchString(username)
}

func isPhone(username string) bool {
	re := regexp.MustCompile(`^\+?[0-9]{10,15}$`)
	return re.MatchString(username)
}

// Send verification email (demo: just print link)
func sendVerificationEmail(email, token string) error {
	link := fmt.Sprintf("http://localhost:8080/verify?username=%s&token=%s", email, token)
	log.Printf("Verification EMAIL link for %s: %s", email, link)
	return nil
}

// Send verification SMS (demo: just print link)
func sendVerificationSMS(phone, token string) error {
	link := fmt.Sprintf("http://localhost:8080/verify?username=%s&token=%s", phone, token)
	log.Printf("Verification SMS link for %s: %s", phone, link)
	return nil
}

// Send password reset email (demo: just print link)
func sendPasswordResetEmail(email, token string) error {
	link := fmt.Sprintf("http://localhost:8080/reset-password?token=%s", token)
	log.Printf("Password RESET link for %s: %s", email, link)
	return nil
}

// Send password reset SMS (demo: just print link)
func sendPasswordResetSMS(phone, token string) error {
	link := fmt.Sprintf("http://localhost:8080/reset-password?token=%s", token)
	log.Printf("Password RESET SMS for %s: %s", phone, link)
	return nil
}

func lookupUserByUsername(username string) (UserInfo, bool) {
	info, err := manager.Vault.GetUserInfoByUsername(username)
	return info, err == nil
}

func lookupUserByPubHex(pubHex string) (UserInfo, bool) {
	info, err := manager.Vault.GetUserInfo(pubHex)
	return info, err == nil
}

// Helper to get public key by user info
func getPublicKeyByUserID(userID string) (string, string, error) {
	pubKey, err := manager.Vault.GetUserPublicKey(userID)
	if err != nil {
		return "", "", err
	}
	return pubKey["PubKeyX"], pubKey["PubKeyY"], nil
}

// --- Main Application ---
func main() {
	// Phase 1: Remove hardcoded secrets - now handled in loadConfig()
	// Initialize manager
	manager = NewManager()

	// Set up routes
	mux := setupRoutes()

	// Configure server
	srv := &http.Server{
		Addr:         manager.Config.Addr,
		Handler:      cors(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	startServer(srv)
}

func setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// Main routes (with rate limiting)
	mux.Handle("/", rateLimitMiddleware(http.HandlerFunc(homeHandler)))
	mux.Handle("/health", rateLimitMiddleware(http.HandlerFunc(health)))
	mux.Handle("/nonce", rateLimitMiddleware(http.HandlerFunc(nonce)))

	// Authentication routes (with rate limiting and login protection)
	mux.Handle("/register", rateLimitMiddleware(http.HandlerFunc(register)))
	mux.Handle("/verify", rateLimitMiddleware(http.HandlerFunc(verifyHandler)))
	mux.Handle("/login", rateLimitMiddleware(http.HandlerFunc(loginSelectionHandler)))
	mux.Handle("/simple-login", rateLimitMiddleware(loginProtectionMiddleware(http.HandlerFunc(simpleLoginHandler(manager.Config)))))
	mux.Handle("/secured-login", rateLimitMiddleware(loginProtectionMiddleware(http.HandlerFunc(securedLoginHandler(manager.Config)))))
	mux.Handle("/logout", rateLimitMiddleware(http.HandlerFunc(logoutHandler(manager.Config))))
	mux.Handle("/sso", rateLimitMiddleware(http.HandlerFunc(ssoHandler(manager.Config))))

	// Password reset routes
	mux.Handle("/forgot-password", rateLimitMiddleware(http.HandlerFunc(forgotPasswordHandler)))
	mux.Handle("/reset-password", rateLimitMiddleware(http.HandlerFunc(resetPasswordHandler)))

	// Protected routes
	mux.Handle("/protected", pasetoMiddleware(manager.Config, protectedHandler()))

	// API endpoints (with rate limiting)
	mux.Handle("/api/status", rateLimitMiddleware(http.HandlerFunc(apiStatusHandler)))
	mux.Handle("/api/userinfo", pasetoMiddleware(manager.Config, http.HandlerFunc(apiUserInfoHandler(manager.Config))))
	mux.Handle("/api/login", rateLimitMiddleware(loginProtectionMiddleware(http.HandlerFunc(apiSimpleLoginHandler(manager.Config)))))
	mux.Handle("/api-demo", rateLimitMiddleware(http.HandlerFunc(apiDemoHandler)))

	return mux
}

func startServer(srv *http.Server) {
	go func() {
		log.Printf("▶ listening on http://localhost%s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Graceful shutdown
	log.Println("⏳ shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	log.Println("✔ shutdown complete")
}

func getNonceWithTimestamp() (string, int64) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", time.Now().Unix()
	}
	nonce := hex.EncodeToString(b)
	timestamp := time.Now().Unix()
	return nonce, timestamp
}

func encryptPrivateKeyD(privd, password string) string {
	// Secure AES-GCM encryption with PBKDF2 key derivation
	privBytes, err := hex.DecodeString(privd)
	if err != nil {
		return ""
	}
	// Generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return ""
	}
	key := pbkdf2.Key([]byte(password), salt, 100_000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return ""
	}
	ciphertext := gcm.Seal(nil, nonce, privBytes, nil)
	// Store salt, nonce, and ciphertext as base64 JSON
	encData := map[string]string{
		"salt":       base64.StdEncoding.EncodeToString(salt),
		"nonce":      base64.StdEncoding.EncodeToString(nonce),
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
	}
	b, _ := json.Marshal(encData)
	return base64.StdEncoding.EncodeToString(b)
}

func decryptPrivateKeyD(encPrivD, password string) string {
	// Secure AES-GCM decryption with PBKDF2 key derivation
	dataBytes, err := base64.StdEncoding.DecodeString(encPrivD)
	if err != nil {
		return ""
	}
	var encData map[string]string
	if err := json.Unmarshal(dataBytes, &encData); err != nil {
		return ""
	}
	salt, err := base64.StdEncoding.DecodeString(encData["salt"])
	if err != nil {
		return ""
	}
	nonce, err := base64.StdEncoding.DecodeString(encData["nonce"])
	if err != nil {
		return ""
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encData["ciphertext"])
	if err != nil {
		return ""
	}
	key := pbkdf2.Key([]byte(password), salt, 100_000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(plain)
}

func getCookie(token string, maxAges ...int) *http.Cookie {
	maxAge := 300
	if len(maxAges) > 0 {
		maxAge = maxAges[0]
	}

	// Phase 1: Dynamic security settings based on environment
	secure := manager.Config.EnableHTTPS || manager.Config.Environment == "production"

	return &http.Cookie{
		Name:     "paseto",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}
}

// --- Paseto Claims Helper ---
func getClaims(sub, nonce string, ts int64) map[string]any {
	return map[string]any{
		"sub": sub,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(expDuration).Unix(),
		"vc": map[string]any{
			"pubKey": sub,
			"nonce":  nonce,
			"ts":     ts,
		},
	}
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Phase 1: Password validation functions
func validatePassword(password string) error {
	if len(password) < passwordMinLength {
		return fmt.Errorf("password must be at least %d characters long", passwordMinLength)
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

func sanitizeInput(input string) string {
	// Remove potentially dangerous characters and normalize
	input = strings.TrimSpace(input)
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	input = strings.ReplaceAll(input, "\"", "&quot;")
	input = strings.ReplaceAll(input, "'", "&#39;")
	return input
}

func validateEmail(email string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	if len(email) == 0 {
		return fmt.Errorf("email cannot be empty")
	}
	if len(email) > 254 {
		return fmt.Errorf("email too long")
	}

	re := regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`)
	if !re.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

func validatePhone(phone string) error {
	phone = strings.TrimSpace(phone)
	if len(phone) == 0 {
		return fmt.Errorf("phone cannot be empty")
	}

	re := regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	if !re.MatchString(phone) {
		return fmt.Errorf("invalid phone format")
	}
	return nil
}
