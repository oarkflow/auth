package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
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
		Name:     "session_token",
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
