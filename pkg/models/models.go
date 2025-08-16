package models

import (
	"sync"
	"time"
)

type RateLimiter struct {
	Requests map[string][]time.Time
	Attempts map[string][]time.Time
	mu       sync.RWMutex
}

type UserInfo struct {
	UserID         int64    `db:"user_id"` // changed from string to int64
	Username       string   `db:"username"`
	LoginType      string   `db:"login_type"`
	MFAEnabled     bool     `db:"mfa_enabled"`
	MFASecret      string   `db:"mfa_secret"`
	MFABackupCodes []string `db:"mfa_backup_codes"`
}

type SchnorrProof struct {
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

// MFA-related types
type MFASetupData struct {
	Secret      string   `json:"secret"`
	QRCode      string   `json:"qr_code"`
	BackupCodes []string `json:"backup_codes"`
}

type MFAVerificationRequest struct {
	Username string `json:"username"`
	Code     string `json:"code"`
}

type LoginStepResponse struct {
	Step       string `json:"step"`
	Message    string `json:"message"`
	RequireMFA bool   `json:"require_mfa,omitempty"`
	UserID     string `json:"user_id,omitempty"`
}
