package handlers

import "github.com/gofiber/fiber/v2"

func LandingPage(c *fiber.Ctx) error {
	return c.Render("index", fiber.Map{
		"Title": "Welcome to the Auth Service",
	})
}

func LoginPage(c *fiber.Ctx) error {
	return c.Render("login", fiber.Map{
		"Title": "Login",
	})
}
