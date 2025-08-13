package handlers

import "github.com/gofiber/fiber/v2"

func Setup(prefix string, router fiber.Router) {
	route := router.Group(prefix)
	route.Get("/", LandingPage)
}
