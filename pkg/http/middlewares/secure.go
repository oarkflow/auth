package middlewares

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/auth/pkg/libs"
)

const (
	sessionTTL = 10 * time.Minute
)

type UserSession struct {
	UserID     string    `json:"user_id"`
	SessionKey []byte    `json:"session_key"`
	HMACKey    []byte    `json:"hmac_key"`
	CreatedAt  time.Time `json:"created_at"`
}

type GenericRequest struct {
	Action    string         `json:"action"`
	Body      map[string]any `json:"body,omitempty"`
	Timestamp int64          `json:"timestamp"`
	Nonce     string         `json:"nonce,omitempty"`
}

type GenericResponse struct {
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

type SecureHandler func(session *UserSession, req GenericRequest) GenericResponse

func SecureMiddleware(handler SecureHandler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get session data from cookies
		sessionKeyB64, ok1 := libs.GetSessionData(c, "session_key")
		hmacKeyB64, ok2 := libs.GetSessionData(c, "hmac_key")
		userID, ok3 := libs.GetSessionData(c, "user_id")
		createdAtStr, ok4 := libs.GetSessionData(c, "session_created_at")

		if !ok1 || !ok2 || !ok3 || !ok4 {
			return c.Status(401).JSON(fiber.Map{"error": "Missing session data"})
		}

		sessionKey, err := base64.StdEncoding.DecodeString(sessionKeyB64)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid session key"})
		}

		hmacKey, err := base64.StdEncoding.DecodeString(hmacKeyB64)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid HMAC key"})
		}

		createdAt, err := time.Parse(time.RFC3339, createdAtStr)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid session timestamp"})
		}

		if time.Since(createdAt) > sessionTTL {
			return c.Status(401).JSON(fiber.Map{"error": "Session expired"})
		}

		userSession := &UserSession{
			UserID:     userID,
			SessionKey: sessionKey,
			HMACKey:    hmacKey,
			CreatedAt:  createdAt,
		}

		// Get the request body
		body := c.Body()

		// Handle compression
		switch c.Get("Content-Encoding") {
		case "gzip":
			gr, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "Failed to decompress gzip"})
			}
			body, err = io.ReadAll(gr)
			gr.Close()
			if err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "Failed to read decompressed data"})
			}
		}

		if len(body) < 32 {
			return c.Status(400).JSON(fiber.Map{"error": "Request too short"})
		}

		reqSig := body[:32]
		reqData := body[32:]

		if !verifyHMAC(reqData, reqSig, userSession.HMACKey) {
			return c.Status(401).JSON(fiber.Map{"error": "HMAC verification failed"})
		}

		reqData, err = decryptAES(reqData, userSession.SessionKey)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Decryption failed"})
		}

		var req GenericRequest
		if err := json.Unmarshal(reqData, &req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid JSON"})
		}

		now := time.Now().Unix()
		if req.Timestamp < now-300 || req.Timestamp > now+300 {
			return c.Status(401).JSON(fiber.Map{"error": "Request timestamp invalid"})
		}

		// Call the handler
		resp := handler(userSession, req)

		// Encrypt the response
		plain, err := json.Marshal(resp)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to encode response"})
		}

		encrypted, err := encryptAES(plain, userSession.SessionKey)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Encryption failed"})
		}
		sig := computeHMAC(encrypted, userSession.HMACKey)
		final := append(sig, encrypted...)

		// Handle compression
		acceptEncoding := c.Get("Accept-Encoding")
		if strings.Contains(acceptEncoding, "gzip") {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			gz.Write(final)
			gz.Close()
			final = buf.Bytes()
			c.Set("Content-Encoding", "gzip")
		}

		c.Set("Content-Type", "application/octet-stream")
		return c.Send(final)
	}
}

func decryptAES(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}

func encryptAES(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return append(nonce, gcm.Seal(nil, nonce, plaintext, nil)...), nil
}

func computeHMAC(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func verifyHMAC(data, sig, key []byte) bool {
	return hmac.Equal(sig, computeHMAC(data, key))
}
