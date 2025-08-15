package responses

import (
	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/auth/pkg/objects"
)

func Render(c *fiber.Ctx, template string, data any, layouts ...string) error {
	if c == nil {
		return fiber.ErrBadRequest
	}
	if template == "" {
		return c.JSON(data)
	}
	c.Set("Content-Type", "text/html; charset=utf-8")
	if objects.ViewEngine == nil {
		return c.Render(template, data, layouts...)
	}
	return objects.ViewEngine.Render(c.Response().BodyWriter(), template, data, layouts...)
}
