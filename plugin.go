package auth

import (
	"embed"
	"log"

	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/auth/pkg/http/middlewares"
	"github.com/oarkflow/auth/pkg/http/routes"
	"github.com/oarkflow/auth/pkg/libs"
	"github.com/oarkflow/auth/pkg/objects"
	"github.com/oarkflow/auth/pkg/storage"
)

//go:embed views
var Assets embed.FS

type Plugin struct {
	App    *fiber.App
	Prefix string
	Assets embed.FS
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

func NewPlugin(prefix string, apps ...*fiber.App) *Plugin {
	var app *fiber.App
	if len(apps) > 0 {
		app = apps[0]
	}
	if prefix == "" {
		prefix = "/"
	}
	plugin := &Plugin{
		Prefix: prefix,
		App:    app,
		Assets: Assets,
	}
	return plugin
}
