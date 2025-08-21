package auth

import (
	"embed"
	"html/template"
	"log"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"

	"github.com/oarkflow/auth/pkg/http/middlewares"
	"github.com/oarkflow/auth/pkg/http/routes"
	"github.com/oarkflow/auth/pkg/libs"
	"github.com/oarkflow/auth/pkg/objects"
	"github.com/oarkflow/auth/pkg/storage"
	"github.com/oarkflow/auth/pkg/utils"
	"github.com/oarkflow/squealx"
	"github.com/oarkflow/squealx/drivers/sqlite"
)

//go:embed auth
var Assets embed.FS

type Plugin struct {
	App                   *fiber.App
	Prefix                string
	LoginSuccessURL       string
	Assets                embed.FS
	DB                    *squealx.DB
	SendNotification      libs.NotificationHandler
	DisabledRoutesHandler func() []string
}

func (p *Plugin) Register() {
	var db *squealx.DB
	cfg := libs.LoadConfig()
	if p.DB != nil {
		db = p.DB
	} else if cfg.DB != nil {
		db = cfg.DB
	} else {
		sqliteDB, err := sqlite.Open("vault.db", "sqlite")
		if err != nil {
			log.Fatalf("failed to open database: %v", err)
		}
		db = sqliteDB
	}
	vault, err := storage.NewDatabaseStorage(db)
	if err != nil {
		log.Fatalf("Failed to initialize DatabaseVaultStorage: %v", err)
	}
	if p.DisabledRoutesHandler != nil {
		cfg.DisableRoutesHandler = p.DisabledRoutesHandler
	}
	manager := libs.NewManager(vault, cfg)
	manager.SendNotification = p.SendNotification
	manager.LoginSuccessURL = p.LoginSuccessURL
	objects.Manager = manager
	if p.App != nil {
		routes.Setup(p.Prefix, p.App)
		routes.ProtectedRoutes(p.App.Group(p.Prefix, middlewares.Verify))
	}
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

func NewPlugin(prefix, loginSuccessURL string, notificationHandler libs.NotificationHandler, apps ...*fiber.App) *Plugin {
	var app *fiber.App
	if len(apps) > 0 {
		app = apps[0]
	}
	if prefix == "" {
		prefix = "/"
	}

	engine := html.NewFileSystem(http.FS(Assets), ".html")
	engine.Reload(true)
	engine.AddFuncMap(map[string]any{
		"unescape": func(s string) template.HTML {
			return template.HTML(s)
		},
		"uris": func() map[string]string {
			return utils.GetURIs()
		},
	})
	objects.ViewEngine = engine
	plugin := &Plugin{
		Prefix:           prefix,
		App:              app,
		Assets:           Assets,
		LoginSuccessURL:  loginSuccessURL,
		SendNotification: notificationHandler,
	}
	return plugin
}
