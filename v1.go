package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oarkflow/paseto/token"
	"github.com/oarkflow/squealx"
	"github.com/oarkflow/squealx/drivers/sqlite"
	"github.com/oarkflow/xid/wuid"
	"golang.org/x/crypto/bcrypt"
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

type SecurityManager struct {
	RateLimiter   *RateLimiter
	LoginAttempts map[string][]time.Time
	BlockedIPs    map[string]time.Time
	mu            sync.RWMutex
}

func NewSecurityManager() *SecurityManager {
	return &SecurityManager{
		RateLimiter: &RateLimiter{
			requests: make(map[string][]time.Time),
			attempts: make(map[string][]time.Time),
		},
		LoginAttempts: make(map[string][]time.Time),
		BlockedIPs:    make(map[string]time.Time),
	}
}

type Manager struct {
	Templates *template.Template
	Vault     VaultStorage
	Config    *Config

	// Authentication state
	UserRegistry     map[string]ecdsa.PublicKey
	UserRegistryMu   sync.RWMutex
	NonceCache       map[string]int64
	NonceCacheMu     sync.Mutex
	LogoutDenylist   map[string]int64
	LogoutDenylistMu sync.Mutex
	Curve            elliptic.Curve

	// Verification storage
	VerificationTokens map[string]string // username -> token
	VerificationStatus map[string]bool   // username -> verified
	VerificationMu     sync.RWMutex

	// Password Reset storage
	PasswordResetTokens map[string]PasswordResetData // token -> reset data
	PasswordResetMu     sync.RWMutex

	// Phase 1: Security Manager
	Security *SecurityManager
}

// Global manager instance
var manager *Manager

func NewManager() *Manager {
	cfg := loadConfig()
	vault, err := NewSQLiteVaultStorage(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize SQLiteVaultStorage: %v", err)
	}
	templates := template.Must(template.ParseGlob("static/*.html"))
	return &Manager{
		Templates: templates,
		Vault:     vault,
		Config:    cfg,

		// Initialize authentication state
		UserRegistry:   make(map[string]ecdsa.PublicKey),
		NonceCache:     make(map[string]int64),
		LogoutDenylist: make(map[string]int64),
		Curve:          elliptic.P256(),

		// Initialize verification storage
		VerificationTokens: make(map[string]string),
		VerificationStatus: make(map[string]bool),

		// Initialize password reset storage
		PasswordResetTokens: make(map[string]PasswordResetData),

		// Initialize security manager
		Security: NewSecurityManager(),
	}
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

// --- Manager Helper Methods ---

// renderTemplate renders a template with the given data
func (m *Manager) renderTemplate(w http.ResponseWriter, tmpl string, data any) {
	err := m.Templates.ExecuteTemplate(w, tmpl, data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}
}

// CleanupExpiredTokens removes expired tokens from the logout denylist
func (m *Manager) CleanupExpiredTokens() {
	m.LogoutDenylistMu.Lock()
	defer m.LogoutDenylistMu.Unlock()
	now := time.Now().Unix()
	for k, v := range m.LogoutDenylist {
		if v < now {
			delete(m.LogoutDenylist, k)
		}
	}
}

// IsTokenDenylisted checks if a token is in the logout denylist
func (m *Manager) IsTokenDenylisted(token string) bool {
	m.LogoutDenylistMu.Lock()
	defer m.LogoutDenylistMu.Unlock()
	exp, found := m.LogoutDenylist[token]
	return found && exp > time.Now().Unix()
}

// AddTokenToDenylist adds a token to the logout denylist
func (m *Manager) AddTokenToDenylist(token string, exp int64) {
	m.LogoutDenylistMu.Lock()
	defer m.LogoutDenylistMu.Unlock()
	m.LogoutDenylist[token] = exp
}

// CleanupExpiredNonces removes expired nonces from the cache
func (m *Manager) CleanupExpiredNonces() {
	m.NonceCacheMu.Lock()
	defer m.NonceCacheMu.Unlock()
	now := time.Now().Unix()
	for k, ts := range m.NonceCache {
		if now-ts > nonceCleanupSec {
			delete(m.NonceCache, k)
		}
	}
}

// IsNonceReplayed checks if a nonce has been used before
func (m *Manager) IsNonceReplayed(nonce string) bool {
	m.NonceCacheMu.Lock()
	defer m.NonceCacheMu.Unlock()
	now := time.Now().Unix()
	ts, found := m.NonceCache[nonce]
	if found && now-ts < nonceCleanupSec {
		return true
	}
	m.NonceCache[nonce] = now
	return false
}

// SetVerificationToken sets a verification token for a username
func (m *Manager) SetVerificationToken(username, token string) {
	m.VerificationMu.Lock()
	defer m.VerificationMu.Unlock()
	m.VerificationTokens[username] = token
	m.VerificationStatus[username] = false
}

// VerifyToken checks and consumes a verification token
func (m *Manager) VerifyToken(username, token string) bool {
	m.VerificationMu.Lock()
	defer m.VerificationMu.Unlock()
	expected, exists := m.VerificationTokens[username]
	if !exists || expected != token {
		return false
	}
	m.VerificationStatus[username] = true
	delete(m.VerificationTokens, username)
	return true
}

// Password Reset Methods
func (m *Manager) SetPasswordResetToken(username, token string) {
	m.PasswordResetMu.Lock()
	defer m.PasswordResetMu.Unlock()
	m.PasswordResetTokens[token] = PasswordResetData{
		Username:  username,
		Token:     token,
		ExpiresAt: time.Now().Add(passwordResetTokenExp),
		Used:      false,
	}
}

func (m *Manager) ValidatePasswordResetToken(token string) (PasswordResetData, bool) {
	m.PasswordResetMu.Lock()
	defer m.PasswordResetMu.Unlock()

	data, exists := m.PasswordResetTokens[token]
	if !exists || data.Used || time.Now().After(data.ExpiresAt) {
		return PasswordResetData{}, false
	}
	return data, true
}

func (m *Manager) ConsumePasswordResetToken(token string) bool {
	m.PasswordResetMu.Lock()
	defer m.PasswordResetMu.Unlock()

	data, exists := m.PasswordResetTokens[token]
	if !exists || data.Used || time.Now().After(data.ExpiresAt) {
		return false
	}

	data.Used = true
	m.PasswordResetTokens[token] = data
	return true
}

func (m *Manager) CleanupExpiredPasswordResetTokens() {
	m.PasswordResetMu.Lock()
	defer m.PasswordResetMu.Unlock()

	now := time.Now()
	for token, data := range m.PasswordResetTokens {
		if data.Used || now.After(data.ExpiresAt) {
			delete(m.PasswordResetTokens, token)
		}
	}
}

// RegisterUserKey adds a user's public key to the registry
func (m *Manager) RegisterUserKey(pubHex string, pubKeyX, pubKeyY []byte) {
	m.UserRegistryMu.Lock()
	defer m.UserRegistryMu.Unlock()
	m.UserRegistry[pubHex] = ecdsa.PublicKey{
		Curve: m.Curve,
		X:     new(big.Int).SetBytes(pubKeyX),
		Y:     new(big.Int).SetBytes(pubKeyY),
	}
}

// --- Vault Storage Interface ---
type VaultStorage interface {
	SetUserInfo(pubHex string, info UserInfo) error
	GetUserInfo(pubHex string) (UserInfo, error)
	GetUserInfoByUsername(username string) (UserInfo, error)
	SetUserSecret(userID, secret string) error
	GetUserSecret(userID string) (string, error)

	SetUserPublicKey(userID string, pubKeyX, pubKeyY string) error
	GetUserPublicKey(userID string) (map[string]string, error)
}

// --- SQLite Vault Storage ---
type SQLiteVaultStorage struct {
	db *squealx.DB
}

func NewSQLiteVaultStorage(dbPath string) (*SQLiteVaultStorage, error) {
	db, err := sqlite.Open(dbPath, "sqlite")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create tables with improved schema and indexes
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		pub_hex TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		user_id TEXT NOT NULL,
		login_type TEXT DEFAULT 'simple' CHECK (login_type IN ('simple', 'secured')),
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		is_active BOOLEAN DEFAULT 1,
		failed_attempts INTEGER DEFAULT 0,
		locked_until DATETIME NULL
	);

	CREATE TABLE IF NOT EXISTS credentials (
		user_id TEXT NOT NULL,
		secret TEXT NOT NULL,
		metadata TEXT,
		secret_type TEXT DEFAULT 'password' NOT NULL,
		integration_type TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (user_id, secret_type)
	);

	-- Phase 1: Add performance indexes
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
	CREATE INDEX IF NOT EXISTS idx_users_login_type ON users(login_type);
	CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
	CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
	CREATE INDEX IF NOT EXISTS idx_credentials_secret_type ON credentials(secret_type);

	-- Phase 1: Add audit log table
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT,
		action TEXT NOT NULL,
		resource TEXT,
		ip_address TEXT,
		user_agent TEXT,
		success BOOLEAN,
		error_message TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to create database schema: %w", err)
	}

	return &SQLiteVaultStorage{db: db}, nil
}

func (v *SQLiteVaultStorage) SetUserInfo(pubHex string, info UserInfo) error {
	_, err := v.db.Exec(`INSERT OR REPLACE INTO users (pub_hex, username, user_id, login_type) VALUES (?, ?, ?, ?)`,
		pubHex, info.Username, info.UserID, info.LoginType)
	return err
}

func (v *SQLiteVaultStorage) GetUserInfo(pubHex string) (UserInfo, error) {
	var info UserInfo
	err := v.db.Get(&info, `SELECT user_id, username, login_type FROM users WHERE pub_hex = ?`, pubHex)
	if err != nil {
		return UserInfo{}, err
	}
	return info, nil
}

func (v *SQLiteVaultStorage) GetUserInfoByUsername(username string) (UserInfo, error) {
	var info UserInfo
	err := v.db.Get(&info, `SELECT user_id, username, login_type FROM users WHERE username = ?`, username)
	if err != nil {
		return UserInfo{}, err
	}
	return info, nil
}

func (v *SQLiteVaultStorage) SetUserSecret(userID, secret string) error {
	_, err := v.db.Exec(`INSERT OR REPLACE INTO credentials (user_id, secret, secret_type) VALUES (?, ?, 'password')`, userID, secret)
	return err
}

func (v *SQLiteVaultStorage) GetUserSecret(userID string) (string, error) {
	var secret string
	err := v.db.Get(&secret, `SELECT secret FROM credentials WHERE user_id = ? AND secret_type = 'password'`, userID)
	if err != nil {
		return "", err
	}
	return secret, nil
}

// New methods for public key storage
func (v *SQLiteVaultStorage) SetUserPublicKey(userID string, pubKeyX, pubKeyY string) error {
	pubKeyJSON, _ := json.Marshal(map[string]string{
		"PubKeyX": pubKeyX,
		"PubKeyY": pubKeyY,
	})
	_, err := v.db.Exec(`INSERT OR REPLACE INTO credentials (user_id, secret, secret_type) VALUES (?, ?, 'public_key')`, userID, string(pubKeyJSON))
	return err
}

func (v *SQLiteVaultStorage) GetUserPublicKey(userID string) (map[string]string, error) {
	var secret string
	err := v.db.Get(&secret, `SELECT secret FROM credentials WHERE user_id = ? AND secret_type = 'public_key'`, userID)
	if err != nil {
		return nil, err
	}
	var pubKey map[string]string
	if err := json.Unmarshal([]byte(secret), &pubKey); err != nil {
		return nil, err
	}
	return pubKey, nil
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

type Config struct {
	Addr         string
	PasetoSecret []byte
	ProofTimeout time.Duration
	// Phase 1: Enhanced Configuration
	Environment    string
	DatabaseURL    string
	EnableHTTPS    bool
	TrustedProxies []string
	LogLevel       string
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

// --- Cryptographic Functions ---
func makeProof(priv *ecdsa.PrivateKey, nonce string, ts int64) (schnorrProof, error) {
	curve := priv.PublicKey.Curve
	r, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return schnorrProof{}, fmt.Errorf("rand.Int: %w", err)
	}
	Rx, Ry := curve.ScalarBaseMult(r.Bytes())
	h := sha256.New()
	h.Write(Rx.Bytes())
	h.Write(Ry.Bytes())
	h.Write([]byte(nonce))
	h.Write([]byte(fmt.Sprintf("%d", ts)))
	c := new(big.Int).SetBytes(h.Sum(nil))
	c.Mod(c, curve.Params().N)
	sx := new(big.Int).Mul(c, priv.D)
	s := new(big.Int).Add(r, sx)
	s.Mod(s, curve.Params().N)
	return schnorrProof{
		R:       hex.EncodeToString(append(Rx.Bytes(), Ry.Bytes()...)),
		S:       hex.EncodeToString(s.Bytes()),
		PubKeyX: fmt.Sprintf("%064x", priv.PublicKey.X),
		PubKeyY: fmt.Sprintf("%064x", priv.PublicKey.Y),
		Nonce:   nonce,
		Ts:      ts,
	}, nil
}

func generateProof(privateKey string, nonce string, ts int64) schnorrProof {
	privD, err := hex.DecodeString(privateKey)
	if err != nil {
		return schnorrProof{}
	}
	curve := elliptic.P256()
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = new(big.Int).SetBytes(privD)
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(priv.D.Bytes())
	proof, err := makeProof(priv, nonce, ts)
	if err != nil {
		return schnorrProof{}
	}
	return proof
}

func verifyProof(p *schnorrProof) error {
	now := time.Now().Unix()
	if now-p.Ts > 60 || p.Ts-now > 5 {
		return fmt.Errorf("timestamp outside window")
	}
	rb, err := hex.DecodeString(p.R)
	if err != nil || len(rb) != 64 {
		return fmt.Errorf("invalid R encoding")
	}
	sx, err := hex.DecodeString(p.S)
	if err != nil {
		return fmt.Errorf("invalid S encoding")
	}
	pubXb, err := hex.DecodeString(p.PubKeyX)
	if err != nil {
		return fmt.Errorf("invalid PubKeyX encoding")
	}
	pubYb, err := hex.DecodeString(p.PubKeyY)
	if err != nil {
		return fmt.Errorf("invalid PubKeyY encoding")
	}
	Rx := new(big.Int).SetBytes(rb[:32])
	Ry := new(big.Int).SetBytes(rb[32:])
	s := new(big.Int).SetBytes(sx)
	pubX := new(big.Int).SetBytes(pubXb)
	pubY := new(big.Int).SetBytes(pubYb)
	curve := elliptic.P256()
	h := sha256.New()
	h.Write(Rx.Bytes())
	h.Write(Ry.Bytes())
	h.Write([]byte(p.Nonce))
	h.Write([]byte(fmt.Sprintf("%d", p.Ts)))
	c := new(big.Int).SetBytes(h.Sum(nil))
	c.Mod(c, curve.Params().N)
	Lx, Ly := curve.ScalarBaseMult(s.Bytes())
	Cx, Cy := curve.ScalarMult(pubX, pubY, c.Bytes())
	Rx2, Ry2 := curve.Add(Rx, Ry, Cx, Cy)
	lxBytes := Lx.Bytes()
	rx2Bytes := Rx2.Bytes()
	lyBytes := Ly.Bytes()
	ry2Bytes := Ry2.Bytes()
	if len(lxBytes) != len(rx2Bytes) {
		if len(lxBytes) < len(rx2Bytes) {
			tmp := make([]byte, len(rx2Bytes))
			copy(tmp[len(rx2Bytes)-len(lxBytes):], lxBytes)
			lxBytes = tmp
		} else {
			tmp := make([]byte, len(lxBytes))
			copy(tmp[len(lxBytes)-len(rx2Bytes):], rx2Bytes)
			rx2Bytes = tmp
		}
	}
	if len(lyBytes) != len(ry2Bytes) {
		if len(lyBytes) < len(ry2Bytes) {
			tmp := make([]byte, len(ry2Bytes))
			copy(tmp[len(ry2Bytes)-len(lyBytes):], lyBytes)
			lyBytes = tmp
		} else {
			tmp := make([]byte, len(lyBytes))
			copy(tmp[len(lyBytes)-len(ry2Bytes):], ry2Bytes)
			ry2Bytes = tmp
		}
	}
	if subtle.ConstantTimeCompare(lxBytes, rx2Bytes) != 1 || subtle.ConstantTimeCompare(lyBytes, ry2Bytes) != 1 {
		return fmt.Errorf("invalid Schnorr proof")
	}
	return nil
}

func generateKeyPair() (string, string, string) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKeyX := hex.EncodeToString(priv.PublicKey.X.Bytes())
	pubKeyY := hex.EncodeToString(priv.PublicKey.Y.Bytes())
	privD := hex.EncodeToString(priv.D.Bytes())
	return pubKeyX, pubKeyY, privD
}

// --- Helper Functions ---
func padHex(s string) string {
	return fmt.Sprintf("%064s", strings.ToLower(s))
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

// --- Configuration Functions ---
func loadConfig() *Config {
	addr := getEnv("LISTEN_ADDR", ":8080")
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// Don't set a default in production
		if getEnv("ENVIRONMENT", "development") == "production" {
			log.Fatal("JWT_SECRET must be set in production")
		}
		log.Println("Warning: Using default JWT_SECRET for development")
		secret = "ca1493f9b638c47219bb82db9843a086"
	}

	ptSec := getEnv("PROOF_TIMEOUTSEC", "5")
	pt, err := time.ParseDuration(ptSec + "s")
	if err != nil {
		log.Printf("invalid PROOF_TIMEOUTSEC, defaulting to 5s")
		pt = 5 * time.Second
	}

	// Phase 1: Enhanced configuration
	environment := getEnv("ENVIRONMENT", "development")
	databaseURL := getEnv("DATABASE_URL", "vault.db")
	enableHTTPS := getEnv("ENABLE_HTTPS", "false") == "true"
	logLevel := getEnv("LOG_LEVEL", "info")

	// Parse trusted proxies
	var trustedProxies []string
	if proxies := os.Getenv("TRUSTED_PROXIES"); proxies != "" {
		trustedProxies = strings.Split(proxies, ",")
		for i, proxy := range trustedProxies {
			trustedProxies[i] = strings.TrimSpace(proxy)
		}
	}

	return &Config{
		Addr:           addr,
		PasetoSecret:   []byte(secret),
		ProofTimeout:   pt,
		Environment:    environment,
		DatabaseURL:    databaseURL,
		EnableHTTPS:    enableHTTPS,
		TrustedProxies: trustedProxies,
		LogLevel:       logLevel,
	}
}

func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
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

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	manager.renderTemplate(w, "index.html", nil)
}

func apiDemoHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "api-demo.html")
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

// --- Basic Handlers ---
func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
	loginType := r.FormValue("loginType")

	if username == "" || password == "" {
		renderErrorPage(w, http.StatusBadRequest, "Missing Required Information",
			"Username and password are required for registration.",
			"Please provide both a valid username (email or phone) and a secure password.",
			"Missing username or password fields", "/register")
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
		http.SetCookie(w, getCookie(tokenStr))
		http.Redirect(w, r.WithContext(ctx), "/protected", http.StatusSeeOther)
	}
}

// --- Logout Handler ---
func logoutHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			manager.renderTemplate(w, "logout.html", nil)
			return
		}
		tokenStr := ""
		cookie, err := r.Cookie("paseto")
		if err == nil {
			tokenStr = cookie.Value
		} else if r.Header.Get("Authorization") != "" {
			tokenStr = r.Header.Get("Authorization")
		}
		if tokenStr == "" {
			renderErrorPage(w, http.StatusBadRequest, "No Authentication Token",
				"No authentication token found for logout.",
				"You don't appear to be logged in. Please log in first if you want to access protected areas.",
				"No paseto cookie or Authorization header found", "/login")
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
		http.SetCookie(w, getCookie("", -1))
		http.Redirect(w, r, "/", http.StatusSeeOther)
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

		if username == "" || password == "" {
			renderErrorPage(w, http.StatusBadRequest, "Missing Login Information",
				"Username and password are required for login.",
				"Please provide both your username and password.",
				"Missing username or password fields", "/simple-login")
			return
		}

		// Phase 1: Enhanced input validation and sanitization
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
			// Phase 1: Record failed login attempt
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
			// Phase 1: Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Invalid Credentials",
				"The username or password you entered is incorrect.",
				"Please check your credentials and try again, or register for a new account.",
				"Password hash not found for user", "/simple-login")
			return
		}

		// Verify password
		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			// Phase 1: Record failed login attempt
			manager.Security.RecordFailedLogin(loginIdentifier)
			renderErrorPage(w, http.StatusUnauthorized, "Invalid Credentials",
				"The username or password you entered is incorrect.",
				"Please check your credentials and try again.",
				"Password verification failed", "/simple-login")
			return
		}

		// Phase 1: Clear failed login attempts on successful login
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

		// Set cookie and redirect to protected area
		http.SetCookie(w, getCookie(tokenStr))
		http.Redirect(w, r, "/protected", http.StatusSeeOther)
	}
}

// Secured Login Handler - Cryptographic proof-based authentication
func securedLoginHandler(cfg *Config) http.HandlerFunc {
	return loginHandler(cfg) // Use existing sophisticated login
}

// Login selection handler
func loginSelectionHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user provided a username to show their preferred method
	username := r.URL.Query().Get("username")
	var userInfo UserInfo
	var hasUser bool

	if username != "" {
		userInfo, hasUser = lookupUserByUsername(username)
	}

	manager.renderTemplate(w, "login-selection.html", map[string]any{
		"HasUser":  hasUser,
		"UserInfo": userInfo,
		"Username": username,
	})
}

// --- API Handlers ---
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
		cookie, err := r.Cookie("paseto")
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
				"id":       info.UserID,
				"username": info.Username,
				"pubKeyX":  pubKeyX,
				"pubKeyY":  pubKeyY,
				"pubHex":   pubHex,
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

		// Set cookie
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

// --- Middleware ---
func pasetoMiddleware(cfg *Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := ""
		cookie, err := r.Cookie("paseto")
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
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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

func verifyProofWithReplay(p *schnorrProof) error {
	manager.CleanupExpiredNonces()
	if manager.IsNonceReplayed(p.Nonce) {
		return fmt.Errorf("nonce replayed")
	}
	return verifyProof(p)
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
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

// Phase 1: Rate Limiting and Security Functions
func (s *SecurityManager) IsRateLimited(identifier string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	requests, exists := s.RateLimiter.requests[identifier]
	if !exists {
		return false
	}

	// Count requests in the last minute
	count := 0
	for _, reqTime := range requests {
		if now.Sub(reqTime) < time.Minute {
			count++
		}
	}

	return count >= maxRequestsPerMin
}

func (s *SecurityManager) RecordRequest(identifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if s.RateLimiter.requests[identifier] == nil {
		s.RateLimiter.requests[identifier] = make([]time.Time, 0)
	}

	// Add current request
	s.RateLimiter.requests[identifier] = append(s.RateLimiter.requests[identifier], now)

	// Clean up old requests (older than 1 minute)
	filtered := make([]time.Time, 0)
	for _, reqTime := range s.RateLimiter.requests[identifier] {
		if now.Sub(reqTime) < time.Minute {
			filtered = append(filtered, reqTime)
		}
	}
	s.RateLimiter.requests[identifier] = filtered
}

func (s *SecurityManager) IsLoginBlocked(identifier string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	attempts, exists := s.LoginAttempts[identifier]
	if !exists {
		return false
	}

	// Count failed attempts in the cooldown period
	count := 0
	for _, attemptTime := range attempts {
		if now.Sub(attemptTime) < loginCooldownPeriod {
			count++
		}
	}

	return count >= maxLoginAttempts
}

func (s *SecurityManager) RecordFailedLogin(identifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if s.LoginAttempts[identifier] == nil {
		s.LoginAttempts[identifier] = make([]time.Time, 0)
	}

	s.LoginAttempts[identifier] = append(s.LoginAttempts[identifier], now)

	// Clean up old attempts
	filtered := make([]time.Time, 0)
	for _, attemptTime := range s.LoginAttempts[identifier] {
		if now.Sub(attemptTime) < loginCooldownPeriod {
			filtered = append(filtered, attemptTime)
		}
	}
	s.LoginAttempts[identifier] = filtered
}

func (s *SecurityManager) ClearLoginAttempts(identifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.LoginAttempts, identifier)
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
