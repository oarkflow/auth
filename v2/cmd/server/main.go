package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"

	v2 "github.com/oarkflow/auth/v2"
	"github.com/oarkflow/auth/v2/http/handlers"
	"github.com/oarkflow/auth/v2/objects"
)

func main() {
	objects.Manager = v2.NewManager()
	engine := html.New("./views", ".html")
	app := fiber.New(fiber.Config{Views: engine})
	handlers.Setup("/", app)
	if err := app.Listen(":3000"); err != nil {
		log.Fatal(err)
	}
}
