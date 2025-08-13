package middlewares

import (
	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/paseto/token"

	"github.com/oarkflow/auth/v2/objects"
)

func SendError(c *fiber.Ctx, status int, message string) error {
	contentType := c.Get("Content-Type")
	if contentType == fiber.MIMEApplicationJSON || contentType == fiber.MIMEApplicationJSONCharsetUTF8 {
		return c.Status(status).JSON(fiber.Map{
			"error": message,
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
	decTok, err := token.DecryptToken(tokenStr, objects.Manager.Config.PasetoSecret)
	if err != nil {
		return SendError(c, fiber.StatusUnauthorized, "invalid session")
	}
	claims := decTok.Claims
	c.Locals("user", claims["sub"])
	c.Locals("claims", claims)
	c.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Set("Pragma", "no-cache")
	c.Set("Expires", "0")
	return c.Next()
}
