package pkg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"
)

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
	vault, err := NewDatabaseVaultStorage(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize DatabaseVaultStorage: %v", err)
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
	for token, exp := range m.LogoutDenylist {
		if exp < now {
			delete(m.LogoutDenylist, token)
		}
	}
}

// IsTokenDenylisted checks if a token is in the logout denylist
func (m *Manager) IsTokenDenylisted(token string) bool {
	m.LogoutDenylistMu.Lock()
	defer m.LogoutDenylistMu.Unlock()
	_, found := m.LogoutDenylist[token]
	return found
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
