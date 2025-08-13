package main

import (
	"html/template"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"

	v2 "github.com/oarkflow/auth/v2"
	"github.com/oarkflow/auth/v2/http/handlers"
	"github.com/oarkflow/auth/v2/http/middlewares"
	"github.com/oarkflow/auth/v2/objects"
)

func main() {
	objects.Manager = v2.NewManager()
	engine := html.New("./views", ".html")
	engine.Reload(true)
	engine.AddFuncMap(map[string]any{
		"unescape": func(s string) template.HTML {
			return template.HTML(s)
		},
		"uris": func() map[string]string {
			return map[string]string{
				"Landing":        handlers.LandingURI,
				"App":            handlers.AppURI,
				"Login":          handlers.LoginURI,
				"Register":       handlers.RegisterURI,
				"Verify":         handlers.VerifyURI,
				"ForgotPassword": handlers.ForgotPasswordURI,
				"OneTime":        handlers.OneTimeURI,
				"SimpleLogin":    handlers.SimpleLoginURI,
				"SecuredLogin":   handlers.SecuredLoginURI,
				"MFAVerify":      handlers.MFAVerifyURI,
				"Logout":         handlers.LogoutURI,
				"UserInfo":       handlers.UserInfoURI,
				"MFASetup":       handlers.MFASetupURI,
				"MFADisable":     handlers.MFADisableURI,
				"MFABackupCodes": handlers.MFABackupCodesURI,
			}
		},
	})
	app := fiber.New(fiber.Config{Views: engine})
	handlers.Setup("/", app)
	handlers.ProtectedRoutes(app.Group("/", middlewares.Verify))
	if err := app.Listen(":3000"); err != nil {
		log.Fatal(err)
	}
}
