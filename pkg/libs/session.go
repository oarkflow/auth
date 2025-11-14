package libs

import (
	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/auth/pkg/objects"
	"github.com/oarkflow/auth/pkg/utils"
)

// SetSessionData stores temporary data in a session cookie (for MFA setup)
// Note: This is a simple implementation. In production, consider using secure session storage.
func SetSessionData(c *fiber.Ctx, key, value string) {
	enableHTTPS := objects.Config.GetBool("app.https")
	appEnv := objects.Config.GetString("app.env")
	cookie := utils.GetCookie(enableHTTPS, appEnv, "temp_"+key, value, 600)
	c.Cookie(cookie)
}

// GetSessionData retrieves temporary data from session cookie
func GetSessionData(c *fiber.Ctx, key string) (string, bool) {
	cookie := c.Cookies("temp_" + key)
	if cookie == "" {
		return "", false
	}
	return cookie, true
}

// ClearSessionData removes temporary session data
func ClearSessionData(c *fiber.Ctx, key string) {
	enableHTTPS := objects.Config.GetBool("app.https")
	appEnv := objects.Config.GetString("app.env")
	cookie := utils.GetCookie(enableHTTPS, appEnv, "temp_"+key, "", -1)
	c.Cookie(cookie)
}
