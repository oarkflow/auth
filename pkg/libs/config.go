package libs

import (
	"log"
	"strings"
	"time"

	"github.com/oarkflow/squealx"
	"github.com/oarkflow/squealx/drivers/sqlite"

	"github.com/oarkflow/auth/pkg/objects"
)

type Config struct {
	Secret                []byte
	ProofTimeout          time.Duration
	DB                    *squealx.DB
	CORSOrigins           []string
	SessionTimeout        time.Duration
	MaxLoginAttempts      int
	RateLimitRequests     int
	RateLimitWindow       time.Duration
	EnableSecurityHeaders bool
	EnableAuditLogging    bool
	PasswordPolicy        PasswordPolicyConfig
}

type PasswordPolicyConfig struct {
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireDigit   bool
	RequireSpecial bool
	MaxAge         time.Duration
}

// --- Configuration Functions ---
func LoadConfig() *Config {
	secret := objects.Config.GetString("auth.secret")
	pt := objects.Config.GetDuration("auth.proof_timeout", "5s")
	// Production-ready security configurations
	corsOrigins := strings.Split(objects.Config.GetString("auth.cors_origins"), ",")
	sessionTimeout := objects.Config.GetDuration("auth.session_timeout", "3600s")
	maxLoginAttempts := objects.Config.GetInt("auth.max_login_attempts", 5)
	rateLimitRequests := objects.Config.GetInt("auth.rate_limit_requests", 100)
	rateLimitWindow := objects.Config.GetDuration("auth.rate_limit_window", "1m")
	enableSecurityHeaders := objects.Config.GetBool("auth.enable_security_headers", true)
	enableAuditLogging := objects.Config.GetBool("auth.enable_audit_logging", false)

	passwordPolicy := PasswordPolicyConfig{
		MinLength:      8,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
		MaxAge:         90 * 24 * time.Hour,
	}
	db, err := sqlite.Open("vault.db", "sqlite")
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	return &Config{
		DB:                    db,
		Secret:                []byte(secret),
		ProofTimeout:          pt,
		CORSOrigins:           corsOrigins,
		SessionTimeout:        sessionTimeout,
		MaxLoginAttempts:      maxLoginAttempts,
		RateLimitRequests:     rateLimitRequests,
		RateLimitWindow:       rateLimitWindow,
		EnableSecurityHeaders: enableSecurityHeaders,
		EnableAuditLogging:    enableAuditLogging,
		PasswordPolicy:        passwordPolicy,
	}
}
