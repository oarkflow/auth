package middlewares

import (
	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/paseto/token"

	"github.com/oarkflow/auth/pkg/objects"
)

func SendError(c *fiber.Ctx, status int, message string) error {
	// Store last visited URI in a cookie for redirect after login
	lastURI := c.OriginalURL()
	c.Cookie(&fiber.Cookie{
		Name:     "last_visited_uri",
		Value:    lastURI,
		Path:     "/",
		HTTPOnly: true,
	})
	contentType := c.Get("Content-Type")
	if contentType == fiber.MIMEApplicationJSON || contentType == fiber.MIMEApplicationJSONCharsetUTF8 {
		return c.Status(status).JSON(fiber.Map{
			"success": false,
			"error":   message,
			"status":  status,
		})
	}
	return c.Status(status).Redirect("/login")
}

func Verify(c *fiber.Ctx) error {
	tokenStr := ""
	cookie := c.Cookies("session_token")
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
	objects.Manager.CleanupExpiredTokens()

	if objects.Manager.IsTokenDenylisted(tokenStr) {
		return SendError(c, fiber.StatusUnauthorized, "session expired")
	}
	secret := objects.Config.GetString("auth.secret")
	decTok, err := token.DecryptToken(tokenStr, []byte(secret))
	if err != nil {
		return SendError(c, fiber.StatusUnauthorized, "invalid session")
	}
	claims := decTok.Claims
	pubHex, _ := claims["sub"].(string)
	userInfo, exists := objects.Manager.LookupUserByPubHex(pubHex)
	if !exists {
		return SendError(c, fiber.StatusUnauthorized, "user not found")
	}
	c.Locals("userInfo", userInfo)
	c.Locals("user_id", userInfo.UserID)
	c.Locals("user", claims["sub"])
	c.Locals("claims", claims)
	c.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Set("Pragma", "no-cache")
	c.Set("Expires", "0")
	return c.Next()
}
