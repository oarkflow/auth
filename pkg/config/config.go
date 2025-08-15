package config

import (
	"github.com/oarkflow/auth/pkg/objects"
)

type Config struct{}

func (a *Config) Prefix() string {
	return "auth"
}

func (a *Config) Load() {
	objects.Config.Add("app.name", "Auth")
	objects.Config.Add("app.version", "1.0.0")
	objects.Config.Add("app.env", "development")
	objects.Config.Add("app.https", false)
	objects.Config.Add(a.Prefix(), map[string]any{
		"secret":          objects.Config.Env("AUTH_SECRET", "OdR4DlWhZk6osDd0qXLdVT88lHOvj14L"),
		"session_name":    objects.Config.Env("AUTH_SESSION_NAME", "session_token"),
		"session_timeout": objects.Config.Env("AUTH_SESSION_TIMEOUT", "24h"),

		"proof_timeout": objects.Config.Env("AUTH_PROOF_TIMEOUT", "5m"),

		"cors_origin":        objects.Config.Env("AUTH_CORS_ORIGIN", "*"),
		"max_login_attempts": objects.Config.Env("AUTH_MAX_LOGIN_ATTEMPTS", 5),

		"rate_limit_requests": objects.Config.Env("AUTH_RATE_LIMIT_REQUESTS", 100),
		"rate_limit_window":   objects.Config.Env("AUTH_RATE_LIMIT_WINDOW", "1m"),

		"enable_security_headers": objects.Config.Env("AUTH_ENABLE_SECURITY_HEADERS", true),
		"enable_audit_logging":    objects.Config.Env("AUTH_ENABLE_AUDIT_LOGGING", true),
	})
}
