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

type Manager struct {
	Templates *template.Template
	Vault     VaultStorage
	Config    *Config
}

func NewManager() *Manager {
	cfg := loadConfig()
	vault, err := NewSQLiteVaultStorage("vault.db")
	if err != nil {
		log.Fatalf("Failed to initialize SQLiteVaultStorage: %v", err)
	}
	templates := template.Must(template.ParseGlob("static/*.html"))
	return &Manager{
		Templates: templates,
		Vault:     vault,
		Config:    cfg,
	}
}

func (m *Manager) renderTemplate(w http.ResponseWriter, tmpl string, data any) {
	err := m.Templates.ExecuteTemplate(w, tmpl, data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
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
		return nil, err
	}
	// Create tables if not exist
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		pub_hex TEXT PRIMARY KEY,
		username TEXT UNIQUE,
		user_id TEXT,
		login_type TEXT DEFAULT 'simple',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS credentials (
		user_id TEXT,
		secret TEXT,
		metadata TEXT,
		secret_type TEXT DEFAULT 'password',
		integration_type TEXT,
		PRIMARY KEY (user_id, secret_type)
	);
	`)
	if err != nil {
		return nil, err
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

// --- Global Vault Instance ---
var (
	userRegistry     = make(map[string]ecdsa.PublicKey)
	userRegistryMu   sync.RWMutex
	nonceCache       = make(map[string]int64)
	nonceCacheMu     sync.Mutex
	logoutDenylist   = make(map[string]int64)
	logoutDenylistMu sync.Mutex
	curve            = elliptic.P256()
)

// Store pending verifications for email and phone
var (
	verificationTokens = make(map[string]string) // username -> token
	verificationStatus = make(map[string]bool)   // username -> verified
	verificationMu     sync.RWMutex
)

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

type schnorrProof struct {
	R       string `json:"R"`
	S       string `json:"S"`
	PubKeyX string `json:"pubKeyX"`
	PubKeyY string `json:"pubKeyY"`
	Nonce   string `json:"nonce"`
	Ts      int64  `json:"ts"`
}

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

type UserInfo struct {
	UserID    string `db:"user_id"`
	Username  string `db:"username"`
	LoginType string `db:"login_type"`
}

// --- Helper Functions ---
func padHex(s string) string {
	return fmt.Sprintf("%064s", strings.ToLower(s))
}

var manager *Manager

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

// --- Config struct and loadConfig function ---
type Config struct {
	Addr         string
	PasetoSecret []byte
	ProofTimeout time.Duration
}

func loadConfig() *Config {
	addr := getEnv("LISTEN_ADDR", ":8080")
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET must be set")
	}
	ptSec := getEnv("PROOF_TIMEOUTSEC", "5")
	pt, err := time.ParseDuration(ptSec + "s")
	if err != nil {
		log.Printf("invalid PROOF_TIMEOUTSEC, defaulting to 5s")
		pt = 5 * time.Second
	}
	return &Config{
		Addr:         addr,
		PasetoSecret: []byte(secret),
		ProofTimeout: pt,
	}
}

func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// --- Main ---
func main() {
	os.Setenv("JWT_SECRET", "ca1493f9b638c47219bb82db9843a086")

	manager = NewManager()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		manager.renderTemplate(w, "index.html", nil)
	})
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/nonce", nonce)
	mux.HandleFunc("/register", register)
	mux.HandleFunc("/verify", verifyHandler)

	// Login routes
	mux.HandleFunc("/login", loginSelectionHandler)
	mux.HandleFunc("/simple-login", simpleLoginHandler(manager.Config))
	mux.HandleFunc("/secured-login", securedLoginHandler(manager.Config))

	mux.HandleFunc("/logout", logoutHandler(manager.Config))
	mux.Handle("/protected", pasetoMiddleware(manager.Config, protectedHandler()))
	mux.HandleFunc("/sso", ssoHandler(manager.Config))

	// API endpoints
	mux.HandleFunc("/api/status", apiStatusHandler)
	mux.Handle("/api/userinfo", pasetoMiddleware(manager.Config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiUserInfoHandler(manager.Config)(w, r)
	})))
	mux.HandleFunc("/api/login", apiSimpleLoginHandler(manager.Config))

	// Serve API demo page
	mux.HandleFunc("/api-demo", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "api-demo.html")
	})

	srv := &http.Server{
		Addr:         manager.Config.Addr,
		Handler:      cors(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("▶ listening on http://localhost%s", manager.Config.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("⏳ shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	log.Println("✔ shutdown complete")
}

// --- Handlers ---
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
	verificationMu.Lock()
	verificationTokens[username] = token
	verificationStatus[username] = false
	verificationMu.Unlock()

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
	verificationMu.Lock()
	defer verificationMu.Unlock()
	expected, exists := verificationTokens[username]
	if !exists || expected != token {
		renderErrorPage(w, http.StatusBadRequest, "Invalid Verification",
			"This verification link is either invalid or has already been used.",
			"The link may have expired or been used already. Please try registering again to get a new verification link.",
			"Verification token does not match or does not exist", "/register")
		return
	}
	verificationStatus[username] = true
	delete(verificationTokens, username)

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
	userRegistryMu.Lock()
	userRegistry[pubHex] = ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes([]byte(pubx)), Y: new(big.Int).SetBytes([]byte(puby))}
	userRegistryMu.Unlock()
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
	return &http.Cookie{
		Name:     "paseto",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}
}

// --- Paseto Claims Helper ---
var expDuration = 15 * time.Minute

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
			logoutDenylistMu.Lock()
			exp, found := logoutDenylist[tokenStr]
			logoutDenylistMu.Unlock()
			if found && exp > time.Now().Unix() {
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
		logoutDenylistMu.Lock()
		exp, found := logoutDenylist[tokenStr]
		logoutDenylistMu.Unlock()
		if found && exp > time.Now().Unix() {
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
		logoutDenylistMu.Lock()
		now := time.Now().Unix()
		for k, v := range logoutDenylist {
			if v < now {
				delete(logoutDenylist, k)
			}
		}
		logoutDenylist[tokenStr] = exp
		logoutDenylistMu.Unlock()
		http.SetCookie(w, getCookie("", -1))
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

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
		pubHex := pubx + ":" + puby
		info, exists := lookupUserByPubHex(pubHex)
		if !exists {
			renderErrorPage(w, http.StatusUnauthorized, "Unrecognized Key",
				"This cryptographic key is not associated with any registered user.",
				"Please check that you're using the correct key file, or register for a new account.",
				"Public key not found in user registry", "/register")
			return
		}
		// Validate public key from credentials table
		storedPubX, storedPubY, err := getPublicKeyByUserID(info.UserID)
		if err != nil || storedPubX != pubx || storedPubY != puby {
			renderErrorPage(w, http.StatusUnauthorized, "Key Validation Failed",
				"The cryptographic key does not match our stored credentials.",
				"There may be an issue with your key file or account. Please contact support.",
				"Public key mismatch with stored credentials", "/secured-login")
			return
		}
		passwordHash, err := manager.Vault.GetUserSecret(info.UserID)
		if err != nil {
			renderErrorPage(w, http.StatusUnauthorized, "Account Verification Failed",
				"Could not verify your account password.",
				"There may be an issue with your account setup. Please contact support.",
				fmt.Sprintf("Password hash retrieval failed: %v", err), "/secured-login")
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
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
			renderErrorPage(w, http.StatusUnauthorized, "Cryptographic Proof Failed",
				"The cryptographic proof verification failed.",
				"There was an issue with the authentication process. Please try again.",
				fmt.Sprintf("Proof verification failed: %v", err), "/secured-login")
			return
		}
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

		// Lookup user by username
		info, exists := lookupUserByUsername(username)
		if !exists {
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
			renderErrorPage(w, http.StatusUnauthorized, "Invalid Credentials",
				"The username or password you entered is incorrect.",
				"Please check your credentials and try again, or register for a new account.",
				"Password hash not found for user", "/simple-login")
			return
		}

		// Verify password
		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			renderErrorPage(w, http.StatusUnauthorized, "Invalid Credentials",
				"The username or password you entered is incorrect.",
				"Please check your credentials and try again.",
				"Password verification failed", "/simple-login")
			return
		}

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

// --- API endpoints for frontend integration ---
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
		logoutDenylistMu.Lock()
		now := time.Now().Unix()
		for k, v := range logoutDenylist {
			if v < now {
				delete(logoutDenylist, k)
			}
		}
		exp, found := logoutDenylist[tokenStr]
		logoutDenylistMu.Unlock()

		if found && exp > time.Now().Unix() {
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

// --- Paseto Middleware ---
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
		logoutDenylistMu.Lock()
		now := time.Now().Unix()
		for k, v := range logoutDenylist {
			if v < now {
				delete(logoutDenylist, k)
			}
		}
		exp, found := logoutDenylist[tokenStr]
		logoutDenylistMu.Unlock()
		if found && exp > time.Now().Unix() {
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
	now := time.Now().Unix()
	nonceCacheMu.Lock()
	for k, ts := range nonceCache {
		if now-ts > 60 {
			delete(nonceCache, k)
		}
	}

	ts, found := nonceCache[p.Nonce]
	if found && now-ts < 60 {
		nonceCacheMu.Unlock()
		return fmt.Errorf("nonce replayed")
	}
	nonceCache[p.Nonce] = now
	nonceCacheMu.Unlock()
	return verifyProof(p)
}

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

// ErrorPageData represents the data structure for error page rendering
type ErrorPageData struct {
	Title       string
	StatusCode  int
	Message     string
	Description string
	Technical   string
	RetryURL    string
	ErrorID     string
}

// renderErrorPage renders the error template with proper error data
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
