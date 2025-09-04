package middlewares

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/auth/pkg/objects"
	"github.com/oarkflow/auth/pkg/utils"
)

// RateLimit middleware for protecting endpoints from excessive requests
func RateLimit(c *fiber.Ctx) error {
	return RateLimitWithMax(30)(c) // Default to 30 requests per minute
}

// RateLimitWithMax creates a rate limiting middleware with custom max requests per minute
func RateLimitWithMax(maxRequests int) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get client IP for rate limiting
		clientIP := utils.GetClientIP(c)

		// Create a unique identifier that includes the endpoint path
		endpointID := fmt.Sprintf("%s:%s", clientIP, c.Path())

		// Check if client is rate limited for this specific endpoint
		if objects.Manager.Security().IsRateLimitedWithMax(endpointID, maxRequests) {
			// Log rate limit violation
			utils.LogAuditEvent(c, objects.Manager, nil, utils.AuditActionAccessProtected, utils.StringPtr("rate_limited"), false, utils.StringPtr(fmt.Sprintf("Rate limit exceeded for endpoint %s", c.Path())))
			if c.Accepts(fiber.MIMEApplicationJSON, fiber.MIMETextHTML) == fiber.MIMEApplicationJSON {
				return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
					"error":       "Too many requests",
					"message":     "Please wait before making another request",
					"retry_after": "60", // seconds
				})
			}
			return c.Redirect(utils.LoginURI + "?error=Too+many+requests.+Please+wait+before+trying+again.")

		}

		// Record the request for this specific endpoint
		objects.Manager.Security().RecordRequest(endpointID)

		// Continue to next handler
		return c.Next()
	}
}
