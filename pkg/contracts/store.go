package contracts

import (
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
}
