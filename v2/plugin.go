package v2

import (
	"log"

	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/auth/v2/config"
	"github.com/oarkflow/auth/v2/http/middlewares"
	"github.com/oarkflow/auth/v2/http/routes"
	"github.com/oarkflow/auth/v2/objects"
	"github.com/oarkflow/auth/v2/pkg"
	"github.com/oarkflow/auth/v2/storage"
)

type Plugin struct {
	App        *fiber.App
	ViewEngine fiber.Views
	Prefix     string
}

func (p *Plugin) Register() {
	cfg := config.LoadConfig()
	vault, err := storage.NewDatabaseVaultStorage(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize DatabaseVaultStorage: %v", err)
	}
	objects.Manager = pkg.NewManager(vault, cfg)
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
