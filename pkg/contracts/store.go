package contracts

import (
	"github.com/oarkflow/auth/pkg/models"
)

// --- vault Storage Interface ---
type Storage interface {
	SetUserInfo(pubHex string, info models.UserInfo) error
	GetUserInfo(pubHex string) (models.UserInfo, error)
	GetUserInfoByUsername(username string) (models.UserInfo, error)
	SetUserSecret(userID, secret string) error
	GetUserSecret(userID string) (string, error)
	SetVerificationToken(username, token string, expiresAt int64) error
	VerifyToken(username, token string) (bool, error)
	SetUserPublicKey(userID string, pubKeyX, pubKeyY string) error
	GetUserPublicKey(userID string) (map[string]string, error)
	SetUserMFA(userID string, secret string, backupCodes []string) error
	GetUserMFA(userID string) (string, []string, error)
	EnableMFA(userID string) error
	DisableMFA(userID string) error
	IsUserMFAEnabled(userID string) (bool, error)
	ValidateBackupCode(userID, code string) error
	InvalidateBackupCode(userID, code string) error
	CreatePendingRegistration(username, passwordHash, loginType string) error
	GetPendingRegistration(username string) (string, string, error)
	DeletePendingRegistration(username string) error
}
