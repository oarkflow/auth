package pkg

import (
	"sync"
	"time"
)

// Phase 1: Rate Limiting and Security Structures
type RateLimiter struct {
	requests map[string][]time.Time
	attempts map[string][]time.Time
	mu       sync.RWMutex
}

// Central Authentication System Types
type Client struct {
	ClientID     string    `db:"client_id" json:"client_id"`
	ClientSecret string    `db:"client_secret" json:"client_secret,omitempty"`
	Name         string    `db:"name" json:"name"`
	RedirectURIs []string  `db:"redirect_uris" json:"redirect_uris"`
	Scopes       []string  `db:"scopes" json:"scopes"`
	IsApproved   bool      `db:"is_approved" json:"is_approved"`
	CreatedAt    time.Time `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time `db:"updated_at" json:"updated_at"`
}

type AuthorizationCode struct {
	Code        string    `db:"code" json:"code"`
	ClientID    string    `db:"client_id" json:"client_id"`
	UserID      string    `db:"user_id" json:"user_id"`
	RedirectURI string    `db:"redirect_uri" json:"redirect_uri"`
	Scopes      []string  `db:"scopes" json:"scopes"`
	ExpiresAt   time.Time `db:"expires_at" json:"expires_at"`
	Used        bool      `db:"used" json:"used"`
}

type AccessToken struct {
	Token     string    `db:"token" json:"token"`
	ClientID  string    `db:"client_id" json:"client_id"`
	UserID    string    `db:"user_id" json:"user_id"`
	Scopes    []string  `db:"scopes" json:"scopes"`
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

type RefreshToken struct {
	Token     string    `db:"token" json:"token"`
	ClientID  string    `db:"client_id" json:"client_id"`
	UserID    string    `db:"user_id" json:"user_id"`
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
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
