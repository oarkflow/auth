package contracts

import (
	"github.com/oarkflow/auth/pkg/models"
)

type SecurityManager interface {
	IsRateLimited(identifier string) bool
	RecordRequest(identifier string)
	IsLoginBlocked(identifier string) bool
	RecordFailedLogin(identifier string)
	ClearLoginAttempts(identifier string)
}

type Manager interface {
	CleanupExpiredNonces()
	IsNonceReplayed(nonce string) bool
	SetVerificationToken(username, token string)
	VerifyToken(username, token string) bool
	SetPasswordResetToken(username, token string)
	ValidatePasswordResetToken(token string) (models.PasswordResetData, bool)
	ConsumePasswordResetToken(token string) bool
	CleanupExpiredPasswordResetTokens()
	RegisterUserKey(pubHex string, pubKeyX, pubKeyY []byte)
	LookupUserByUsername(username string) (models.UserInfo, bool)
	LookupUserByPubHex(pubHex string) (models.UserInfo, bool)
	GetPublicKeyByUserID(userID int64) (string, string, error)
	DisabledRoutes() []string
	Vault() Storage
	Security() SecurityManager
	LogoutTracker() LogoutTracker
}

type LogoutTracker interface {
	SetUserLogout(userID int64)
	IsUserLoggedOut(userID int64, authTimestamp int64) bool
	ClearUserLogout(userID int64)
}
