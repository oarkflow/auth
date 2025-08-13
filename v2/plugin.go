package v2

import (
	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/auth/v2/http/middlewares"
	"github.com/oarkflow/auth/v2/http/routes"
	"github.com/oarkflow/auth/v2/objects"
	"github.com/oarkflow/auth/v2/pkg"
)

type Plugin struct {
	App        *fiber.App
	ViewEngine fiber.Views
	Prefix     string
}

func (p *Plugin) Register() {
	objects.Manager = pkg.NewManager()
	routes.Setup(p.Prefix, p.App)
	routes.ProtectedRoutes(p.App.Group(p.Prefix, middlewares.Verify))
}

func (p *Plugin) Init() {
}

func (p *Plugin) Name() string {
	return "Auth"
}

func (p *Plugin) DependsOn() []string {
	return []string{"Database"}
}

func (p *Plugin) Close() error {
	return nil
}

func NewPlugin(prefix string, app *fiber.App, viewEngine fiber.Views) *Plugin {
	if prefix == "" {
		prefix = "/"
	}
	plugin := &Plugin{
		Prefix:     prefix,
		App:        app,
		ViewEngine: viewEngine,
	}
	return plugin
}
