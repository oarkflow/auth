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
	UserID         int64      `db:"user_id"`
	PubHex         string     `db:"pub_hex"`
	Username       string     `db:"username"`
	Name           string     `db:"name"`
	FirstName      string     `db:"first_name"`
	MiddleName     string     `db:"middle_name"`
	LastName       string     `db:"last_name"`
	Status         string     `db:"status"`
	LoginType      string     `db:"login_type"`
	MFAEnabled     bool       `db:"mfa_enabled"`
	IsActive       bool       `db:"is_active"`
	FailedAttempts int        `db:"failed_attempts"`
	LockedUntil    *time.Time `db:"locked_until"`
	CreatedAt      time.Time  `db:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at"`
	MFASecret      string     `db:"mfa_secret"`
	MFABackupCodes []string   `db:"mfa_backup_codes"`
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

// LoginAttempt represents a login attempt entry
type LoginAttempt struct {
	ID          int64     `db:"id"`
	Identifier  string    `db:"identifier"`
	IPAddress   string    `db:"ip_address"`
	UserAgent   *string   `db:"user_agent"`
	Success     bool      `db:"success"`
	AttemptTime time.Time `db:"attempt_time"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID        int64     `db:"id"`
	UserID    *string   `db:"user_id"`
	Action    string    `db:"action"`
	Resource  *string   `db:"resource"`
	IPAddress string    `db:"ip_address"`
	UserAgent *string   `db:"user_agent"`
	Success   bool      `db:"success"`
	ErrorMsg  *string   `db:"error_message"`
	CreatedAt time.Time `db:"created_at"`
}
