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
	DisableSchemas        bool
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
	vault, err := storage.NewDatabaseStorage(db, p.DisableSchemas)
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

// Option is a functional option for configuring the Plugin
type Option func(*Plugin)

// WithPrefix sets the prefix for the plugin routes
func WithPrefix(prefix string) Option {
	return func(p *Plugin) {
		p.Prefix = prefix
	}
}

func WithDisableSchemas(disable bool) Option {
	return func(p *Plugin) {
		p.DisableSchemas = disable
	}
}

// WithLoginSuccessURL sets the URL to redirect to after successful login
func WithLoginSuccessURL(url string) Option {
	return func(p *Plugin) {
		p.LoginSuccessURL = url
	}
}

// WithNotificationHandler sets the notification handler for sending emails/SMS
func WithNotificationHandler(handler libs.NotificationHandler) Option {
	return func(p *Plugin) {
		p.SendNotification = handler
	}
}

// WithApp sets the Fiber app instance
func WithApp(app *fiber.App) Option {
	return func(p *Plugin) {
		p.App = app
	}
}

// WithDB sets the database connection
func WithDB(db *squealx.DB) Option {
	return func(p *Plugin) {
		p.DB = db
	}
}

// WithDisabledRoutesHandler sets the handler for disabled routes
func WithDisabledRoutesHandler(handler func() []string) Option {
	return func(p *Plugin) {
		p.DisabledRoutesHandler = handler
	}
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

// NewPluginWithOptions creates a new Auth plugin with functional options
func NewPluginWithOptions(options ...Option) *Plugin {
	// Default values
	plugin := &Plugin{
		Prefix: "/",
		Assets: Assets,
	}

	// Apply options
	for _, option := range options {
		option(plugin)
	}

	// Initialize template engine
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

	return plugin
}
