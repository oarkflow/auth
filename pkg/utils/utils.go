package utils

import (
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
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/oarkflow/hash"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/pbkdf2"
)

const (
	expDuration       = 15 * time.Minute
	passwordMinLength = 8
)

func HashCheck(password, hashStr, algo, legacyAlgo string) (bool, error) {
	ok, err := hash.Match(password, hashStr, algo)
	if ok || legacyAlgo == "" {
		return ok, err
	}
	return hash.Match(password, hashStr, legacyAlgo)
}

// Detect if username is email or phone
func IsEmail(username string) bool {
	re := regexp.MustCompile(`^[^@]+@[^@]+\.[^@]+$`)
	return re.MatchString(username)
}

func IsPhone(username string) bool {
	re := regexp.MustCompile(`^\+?[0-9]{10,15}$`)
	return re.MatchString(username)
}

// Send verification email (demo: just print link)
func SendVerificationEmail(c *fiber.Ctx, email, token string) error {
	path := c.BaseURL() + VerifyURI + "?username=" + email + "&token=" + token
	log.Printf("Verification EMAIL link for %s: %s", email, path)
	return nil
}

// Send verification SMS (demo: just print link)
func SendVerificationSMS(c *fiber.Ctx, phone, token string) error {
	path := c.BaseURL() + VerifyURI + "?username=" + phone + "&token=" + token
	log.Printf("Verification SMS link for %s: %s", phone, path)
	return nil
}

// Send password reset email (demo: just print link)
func SendPasswordResetEmail(c *fiber.Ctx, email, token string) error {
	path := c.BaseURL() + ResetPasswordURI + "?token=" + token
	log.Printf("Password RESET link for %s: %s", email, path)
	return nil
}

// Send password reset SMS (demo: just print link)
func SendPasswordResetSMS(c *fiber.Ctx, phone, token string) error {
	path := c.BaseURL() + ResetPasswordURI + "?token=" + token
	log.Printf("Password RESET SMS for %s: %s", phone, path)
	return nil
}

func GetNonceWithTimestamp() (string, int64) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", time.Now().Unix()
	}
	nonce := hex.EncodeToString(b)
	timestamp := time.Now().Unix()
	return nonce, timestamp
}

func EncryptPrivateKeyD(privd, password string) string {
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

func DecryptPrivateKeyD(encPrivD, password string) string {
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

func GetCookie(enableHTTPS bool, env, key, val string, maxAges ...int) *fiber.Cookie {
	maxAge := 300
	if len(maxAges) > 0 {
		maxAge = maxAges[0]
	}

	// Phase 1: Dynamic security settings based on environment
	secure := enableHTTPS || env == "production"

	return &fiber.Cookie{
		Name:     key,
		Value:    val,
		Path:     "/",
		HTTPOnly: true,
		Secure:   secure,
		MaxAge:   maxAge,
	}
}

// --- Paseto Claims Helper ---
func GetClaims(sub, nonce string, ts int64) map[string]any {
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

func GetClientIP(c *fiber.Ctx) string {
	if xff := c.Get("X-Forwarded-For"); len(xff) > 0 {
		if comma := strings.IndexByte(xff, ','); comma > 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}

	if xri := c.Get("X-Real-IP"); len(xri) > 0 {
		return strings.TrimSpace(xri)
	}

	// c.IP() is already a string; avoid SplitHostPort if no colon
	ip := c.IP()
	if i := strings.LastIndexByte(ip, ':'); i != -1 {
		return ip[:i]
	}
	return ip
}

// Phase 1: Password validation functions
func ValidatePassword(password string) error {
	if len(password) < passwordMinLength {
		return fmt.Errorf("password must be at least %d characters", passwordMinLength)
	}

	hasUpper, hasLower, hasDigit, hasSpecial := false, false, false, false

	for _, c := range password {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasDigit = true
		case isSpecialChar(c):
			hasSpecial = true
		}

		// Early exit if all found
		if hasUpper && hasLower && hasDigit && hasSpecial {
			return nil
		}
	}

	if !hasUpper {
		return errors.New("must contain uppercase letter")
	}
	if !hasLower {
		return errors.New("must contain lowercase letter")
	}
	if !hasDigit {
		return errors.New("must contain digit")
	}
	if !hasSpecial {
		return errors.New("must contain special character")
	}
	return nil
}

func isSpecialChar(c rune) bool {
	switch c {
	case '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
		'_', '+', '-', '=', '[', ']', '{', '}', '|',
		';', ':', ',', '.', '<', '>', '?':
		return true
	}
	return false
}

func SanitizeInput(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	// Manual replacement in a single pass (faster than ReplaceAll chain)
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		switch r {
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ValidateEmail checks format and constraints without regex or allocations.
func ValidateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return errors.New("email cannot be empty")
	}
	if len(email) > 254 {
		return errors.New("email too long")
	}

	state := 0 // 0 = local, 1 = domain
	localLen := 0
	labelLen := 0
	tldLen := 0
	labelCount := 0
	hasAt := false

	for i := 0; i < len(email); i++ {
		c := email[i]

		if state == 0 { // local part
			if c == '@' {
				if localLen == 0 || i == len(email)-1 {
					return errors.New("invalid email: missing local or domain")
				}
				if localLen > 64 {
					return errors.New("local part too long")
				}
				state = 1
				hasAt = true
				continue
			}
			if !(isAlphaNum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-') {
				return errors.New("invalid character in local part")
			}
			localLen++
		} else { // domain part
			if c == '.' {
				if labelLen == 0 {
					return errors.New("invalid domain: empty label")
				}
				labelCount++
				tldLen = labelLen
				labelLen = 0
				continue
			}
			if !(isAlphaNum(c) || c == '-') {
				return errors.New("invalid character in domain")
			}
			labelLen++
			if labelLen > 63 {
				return errors.New("domain label too long")
			}
		}
	}

	if !hasAt {
		return errors.New("missing @ symbol")
	}
	if labelLen == 0 {
		return errors.New("invalid domain: empty last label")
	}
	tldLen = labelLen
	labelCount++

	if labelCount < 2 {
		return errors.New("missing TLD")
	}
	if tldLen < 2 || tldLen > 63 {
		return errors.New("invalid TLD length")
	}

	return nil
}

// ValidatePhone checks phone format without regex or allocations (E.164-like)
func ValidatePhone(phone string) error {
	phone = strings.TrimSpace(phone)
	if phone == "" {
		return errors.New("phone cannot be empty")
	}

	digitCount := 0
	firstDigitSeen := false

	for i, r := range phone {
		if unicode.IsDigit(r) {
			digitCount++
			if !firstDigitSeen {
				if r == '0' {
					return errors.New("phone cannot start with 0")
				}
				firstDigitSeen = true
			}
		} else if r == '+' {
			if i != 0 {
				return errors.New("'+' must be at start")
			}
		} else if r != ' ' && r != '-' && r != '(' && r != ')' {
			return errors.New("invalid character in phone number")
		}
	}

	if digitCount < 1 || digitCount > 15 {
		return errors.New("invalid phone length")
	}

	return nil
}

// Helpers
func isAlphaNum(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9')
}
