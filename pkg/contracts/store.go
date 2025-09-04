package contracts

import (
	"time"

	"github.com/oarkflow/auth/pkg/models"
)

// --- vault Storage Interface ---
type Storage interface {
	SetUserInfo(pubHex string, info models.UserInfo) error
	GetUserInfo(pubHex string) (models.UserInfo, error)
	GetUserInfoByUsername(username string) (models.UserInfo, error)
	SetUserSecret(userID int64, secret string) error
	GetUserSecret(userID int64) (string, error)
	SetVerificationToken(username, token string, expiresAt int64) error
	VerifyToken(username, token string) (bool, error)
	SetUserPublicKey(userID int64, pubKeyX, pubKeyY string) error
	GetUserPublicKey(userID int64) (map[string]string, error)
	SetUserMFA(userID int64, secret string, backupCodes []string) error
	GetUserMFA(userID int64) (string, []string, error)
	EnableMFA(userID int64) error
	DisableMFA(userID int64) error
	IsUserMFAEnabled(userID int64) (bool, error)
	ValidateBackupCode(userID int64, code string) error
	InvalidateBackupCode(userID int64, code string) error
	CreatePendingRegistration(username, passwordHash, loginType string) error
	GetPendingRegistration(username string) (string, string, error)
	DeletePendingRegistration(username string) error

	// Audit logging methods
	LogAuditEvent(userID *string, action string, resource *string, ipAddress string, userAgent *string, success bool, errorMsg *string) error
	GetAuditLogs(userID *string, limit int, offset int) ([]models.AuditLog, error)

	// Login attempts methods
	RecordLoginAttempt(identifier string, ipAddress string, userAgent *string, success bool) error
	GetRecentLoginAttempts(identifier string, since time.Time) ([]models.LoginAttempt, error)
	ClearOldLoginAttempts(before time.Time) error
	IsLoginBlocked(identifier string, maxAttempts int, window time.Duration) (bool, error)
}
