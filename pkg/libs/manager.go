package libs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/auth/pkg/contracts"
	"github.com/oarkflow/auth/pkg/models"
)

const (
	nonceCleanupSec       = 60
	maxLoginAttempts      = 5
	loginCooldownPeriod   = 15 * time.Minute
	maxRequestsPerMin     = 30
	passwordResetTokenExp = 30 * time.Minute
)

type SecurityManager struct {
	RateLimiter *models.RateLimiter
	storage     contracts.Storage
	mu          sync.RWMutex
}

func NewSecurityManager(storage contracts.Storage) *SecurityManager {
	log.Printf("DEBUG: NewSecurityManager called with storage: %v", storage != nil)
	return &SecurityManager{
		RateLimiter: &models.RateLimiter{
			Requests: make(map[string][]time.Time),
			Attempts: make(map[string][]time.Time),
		},
		storage: storage,
	}
}

// Phase 1: Rate Limiting and Security Functions
func (s *SecurityManager) IsRateLimited(identifier string) bool {
	return s.IsRateLimitedWithMax(identifier, maxRequestsPerMin)
}

func (s *SecurityManager) IsRateLimitedWithMax(identifier string, maxRequests int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	requests, exists := s.RateLimiter.Requests[identifier]
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

	return count >= maxRequests
}

func (s *SecurityManager) RecordRequest(identifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if s.RateLimiter.Requests[identifier] == nil {
		s.RateLimiter.Requests[identifier] = make([]time.Time, 0)
	}

	// Add current request
	s.RateLimiter.Requests[identifier] = append(s.RateLimiter.Requests[identifier], now)

	// Clean up old requests (older than 1 minute)
	filtered := make([]time.Time, 0)
	for _, reqTime := range s.RateLimiter.Requests[identifier] {
		if now.Sub(reqTime) < time.Minute {
			filtered = append(filtered, reqTime)
		}
	}
	s.RateLimiter.Requests[identifier] = filtered
}

func (s *SecurityManager) IsLoginBlocked(identifier string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	blocked, err := s.storage.IsLoginBlocked(identifier, maxLoginAttempts, loginCooldownPeriod)
	if err != nil {
		// Log error but don't block on database errors
		log.Printf("Error checking login block status: %v", err)
		return false
	}
	return blocked
}

func (s *SecurityManager) RecordFailedLogin(identifier string, userAgent *string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Printf("DEBUG: RecordFailedLogin called with identifier: %s, userAgent: %v", identifier, userAgent)

	// Record failed login attempt in database
	// The identifier may contain IP:username format, extract IP
	ipAddress := identifier
	if colonIndex := strings.LastIndex(identifier, ":"); colonIndex > 0 {
		ipAddress = identifier[:colonIndex]
	}

	err := s.storage.RecordLoginAttempt(identifier, ipAddress, userAgent, false)
	if err != nil {
		log.Printf("Error recording failed login attempt: %v", err)
	} else {
		log.Printf("DEBUG: Successfully recorded failed login attempt for identifier: %s", identifier)
	}
}

func (s *SecurityManager) ClearLoginAttempts(identifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Note: With database storage, we don't need to explicitly clear attempts
	// The IsLoginBlocked method will check within the time window
	// This method is kept for interface compatibility
}

type Manager struct {
	vault           contracts.Storage
	Config          *Config
	LoginSuccessURL string
	// Authentication state
	UserRegistry      map[string]ecdsa.PublicKey
	UserRegistryMu    sync.RWMutex
	NonceCache        map[string]int64
	NonceCacheMu      sync.Mutex
	Curve             elliptic.Curve
	UserLogoutTracker contracts.LogoutTracker

	// Verification storage
	VerificationTokens map[string]string // username -> token
	VerificationStatus map[string]bool   // username -> verified
	VerificationMu     sync.RWMutex

	// Password Reset storage
	PasswordResetTokens map[string]models.PasswordResetData // token -> reset data
	PasswordResetMu     sync.RWMutex

	// Phase 1: Security Manager
	security             contracts.SecurityManager
	DisableRoutesHandler func() []string
	SendNotification     NotificationHandler
}

func (m *Manager) Vault() contracts.Storage {
	return m.vault
}

func (m *Manager) Security() contracts.SecurityManager {
	return m.security
}

func (m *Manager) LogoutTracker() contracts.LogoutTracker {
	return m.UserLogoutTracker
}

func (m *Manager) AuditLogger() contracts.AuditLogger {
	return m
}

// AuditLogger implementation
func (m *Manager) LogEvent(userID *string, action string, resource *string, ipAddress string, userAgent *string, success bool, errorMsg *string) {
	// Log asynchronously to avoid blocking the main request
	go func() {
		err := m.vault.LogAuditEvent(userID, action, resource, ipAddress, userAgent, success, errorMsg)
		if err != nil {
			// Log the error but don't fail the main operation
			log.Printf("Failed to log audit event: %v", err)
		}
	}()
}

func (m *Manager) GetLogs(userID *string, limit int, offset int) ([]models.AuditLog, error) {
	return m.vault.GetAuditLogs(userID, limit, offset)
}

func (m *Manager) DisabledRoutes() []string {
	if m.DisableRoutesHandler == nil {
		return []string{}
	}
	return m.DisableRoutesHandler()
}

func NewManager(vaultStorage contracts.Storage, configs ...*Config) *Manager {
	var cfg *Config
	if len(configs) > 0 {
		cfg = configs[0]
	}
	return &Manager{
		vault:                vaultStorage,
		Config:               cfg,
		UserLogoutTracker:    NewUserLogoutTracker(),
		UserRegistry:         make(map[string]ecdsa.PublicKey),
		NonceCache:           make(map[string]int64),
		Curve:                elliptic.P256(),
		VerificationTokens:   make(map[string]string),
		VerificationStatus:   make(map[string]bool),
		PasswordResetTokens:  make(map[string]models.PasswordResetData),
		security:             NewSecurityManager(vaultStorage),
		DisableRoutesHandler: cfg.DisableRoutesHandler,
	}
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
	m.PasswordResetTokens[token] = models.PasswordResetData{
		Username:  username,
		Token:     token,
		ExpiresAt: time.Now().Add(passwordResetTokenExp),
		Used:      false,
	}
}

func (m *Manager) ValidatePasswordResetToken(token string) (models.PasswordResetData, bool) {
	m.PasswordResetMu.Lock()
	defer m.PasswordResetMu.Unlock()

	data, exists := m.PasswordResetTokens[token]
	if !exists || data.Used || time.Now().After(data.ExpiresAt) {
		return models.PasswordResetData{}, false
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

func (manager *Manager) LookupUserByUsername(username string) (models.UserInfo, bool) {
	info, err := manager.vault.GetUserInfoByUsername(username)
	return info, err == nil
}

func (manager *Manager) LookupUserByPubHex(pubHex string) (models.UserInfo, bool) {
	info, err := manager.vault.GetUserInfo(pubHex)
	return info, err == nil
}

// Helper to get public key by user info
func (manager *Manager) GetPublicKeyByUserID(userID int64) (string, string, error) {
	pubKey, err := manager.vault.GetUserPublicKey(userID)
	if err != nil {
		return "", "", err
	}
	return pubKey["PubKeyX"], pubKey["PubKeyY"], nil
}

type NotificationCallback func(*fiber.Ctx, string, string) error

type NotificationHandler struct {
	SendVerificationEmail  NotificationCallback
	SendVerificationSMS    NotificationCallback
	SendPasswordResetEmail NotificationCallback
	SendPasswordResetSMS   NotificationCallback
}
