package auth

import (
	"log"

	"github.com/gofiber/fiber/v2"

	"embed"

	"github.com/oarkflow/auth/pkg/http/middlewares"
	"github.com/oarkflow/auth/pkg/http/routes"
	"github.com/oarkflow/auth/pkg/libs"
	"github.com/oarkflow/auth/pkg/objects"
	"github.com/oarkflow/auth/pkg/storage"
)

//go:embed views
var Assets embed.FS

type Plugin struct {
	App        *fiber.App
	ViewEngine fiber.Views
	Prefix     string
}

func (p *Plugin) Register() {
	cfg := libs.LoadConfig()
	vault, err := storage.NewDatabaseStorage(cfg.DB)
	if err != nil {
		log.Fatalf("Failed to initialize DatabaseVaultStorage: %v", err)
	}
	objects.Manager = libs.NewManager(vault, cfg)
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
