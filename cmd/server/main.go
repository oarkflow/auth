package main

import (
	"html/template"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"

	v2 "github.com/oarkflow/auth"
	"github.com/oarkflow/auth/pkg/utils"
)

func main() {
	engine := html.New("./views", ".html")
	engine.Reload(true)
	engine.AddFuncMap(map[string]any{
		"unescape": func(s string) template.HTML {
			return template.HTML(s)
		},
		"uris": func() map[string]string {
			return utils.GetURIs()
		},
	})
	app := fiber.New(fiber.Config{Views: engine})
	authPlugin := v2.NewPlugin("/", app, engine)
	authPlugin.Register()
	if err := app.Listen(":3000"); err != nil {
		log.Fatal(err)
	}
}
