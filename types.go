package main

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
