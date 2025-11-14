package handlers

import (
	"github.com/oarkflow/auth/pkg/objects"
	"github.com/oarkflow/auth/pkg/utils"
)

// verifyPassword compares plaintext password with bcrypt hash
func verifyPassword(password, hash string) (bool, error) {
	hashAlgo := objects.Config.GetString("auth.password_algo")
	legacyHashAlgo := objects.Config.GetString("auth.legacy_password_algo")
	return utils.HashCheck(password, hash, hashAlgo, legacyHashAlgo)
}
