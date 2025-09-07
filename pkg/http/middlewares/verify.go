package middlewares

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/sujit-baniya/flash"

	"github.com/oarkflow/paseto/token"

	"github.com/oarkflow/auth/pkg/objects"
	"github.com/oarkflow/auth/pkg/utils"
)

func SendError(c *fiber.Ctx, status int, message string) error {
	lastURI := c.OriginalURL()
	// Only store last visited URI if it's not a static asset
	if !isAssetURI(lastURI) {
		c = flash.WithData(c, fiber.Map{"last_visited_uri": lastURI})
	}
	contentType := c.Get("Content-Type")
	if contentType == fiber.MIMEApplicationJSON || contentType == fiber.MIMEApplicationJSONCharsetUTF8 {
		return c.Status(status).JSON(fiber.Map{
			"success": false,
			"error":   message,
			"status":  status,
		})
	}
	return c.Status(status).Redirect("/login?error=" + url.QueryEscape(message))
}

// Helper to check if URI is an asset
func isAssetURI(uri string) bool {
	ext := strings.ToLower(path.Ext(uri))
	return ext != ""
}

func Verify(c *fiber.Ctx) error {
	tokenStr := ""
	sessionName := objects.Config.GetString("auth.session_name")
	if sessionName == "" {
		sessionName = utils.DefaultSessionName
	}
	cookie := c.Cookies(sessionName)
	if cookie != "" {
		tokenStr = cookie
	} else {
		auth := c.Get("Authorization")
		if len(auth) > 7 && auth[:7] == "Bearer " {
			tokenStr = auth[7:]
		} else {
			tokenStr = auth
		}
	}
	if tokenStr == "" {
		return SendError(c, fiber.StatusUnauthorized, "authentication required")
	}
	secret := objects.Config.GetString("auth.secret")
	decTok, err := token.DecryptToken(tokenStr, []byte(secret))
	if err != nil {
		return SendError(c, fiber.StatusUnauthorized, "invalid session")
	}
	claims := decTok.Claims
	claimIP, _ := claims["ip"].(string)
	currentIP := utils.GetClientIP(c)
	if isNotLocalhost(claimIP) && claimIP != currentIP {
		return SendError(c, fiber.StatusUnauthorized, "IP mismatch")
	}
	pubHex, _ := claims["sub"].(string)
	userInfo, exists := objects.Manager.LookupUserByPubHex(pubHex)
	if !exists {
		return SendError(c, fiber.StatusUnauthorized, "user not found")
	}

	// Check if user has been logged out after token was issued
	iat, _ := claims["iat"].(float64)
	if iat > 0 && objects.Manager.LogoutTracker().IsUserLoggedOut(userInfo.UserID, int64(iat)) {
		return SendError(c, fiber.StatusUnauthorized, "session loggout")
	}

	userIDStr := fmt.Sprintf("%d", userInfo.UserID)
	utils.LogAuditEvent(c, objects.Manager, &userIDStr, utils.AuditActionAccessProtected, utils.StringPtr(c.Path()), true, nil)

	c.Locals("userInfo", userInfo)
	c.Locals("user_id", userInfo.UserID)
	c.Locals("user", claims["sub"])
	c.Locals("claims", claims)
	c.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Set("Pragma", "no-cache")
	c.Set("Expires", "0")
	return c.Next()
}

func isNotLocalhost(ip string) bool {
	if ip == "" {
		return true
	}
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "::1") || strings.HasPrefix(ip, "localhost") {
		return false
	}
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") {
		return false
	}
	return true
}
