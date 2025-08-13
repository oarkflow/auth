package handlers

import (
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"

	"github.com/oarkflow/auth/pkg/objects"
	"github.com/oarkflow/auth/pkg/utils"
)

// setSessionData stores temporary data in a session cookie (for MFA setup)
// Note: This is a simple implementation. In production, consider using secure session storage.
func setSessionData(c *fiber.Ctx, key, value string) {
	cookie := utils.GetCookie(objects.Manager.Config.EnableHTTPS, objects.Manager.Config.Environment, "temp_"+key, value, 600)
	c.Cookie(cookie)
}

// getSessionData retrieves temporary data from session cookie
func getSessionData(c *fiber.Ctx, key string) (string, bool) {
	cookie := c.Cookies("temp_" + key)
	if cookie == "" {
		return "", false
	}
	return cookie, true
}

// clearSessionData removes temporary session data
func clearSessionData(c *fiber.Ctx, key string) {
	cookie := utils.GetCookie(objects.Manager.Config.EnableHTTPS, objects.Manager.Config.Environment, "temp_"+key, "", -1)
	c.Cookie(cookie)
}

// verifyPassword compares plaintext password with bcrypt hash
func verifyPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
