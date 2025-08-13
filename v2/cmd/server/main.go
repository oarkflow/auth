package main

import (
	"auth/v2/handlers"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

func main() {
	engine := html.New("./views", ".html")
	app := fiber.New(fiber.Config{Views: engine})
	handlers.Setup("/", app)
	if err := app.Listen(":3000"); err != nil {
		log.Fatal(err)
	}
}
