package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr         string
	PasetoSecret []byte
	ProofTimeout time.Duration
	// Phase 1: Enhanced Configuration
	Environment    string
	DatabaseURL    string
	EnableHTTPS    bool
	TrustedProxies []string
	LogLevel       string
	// Production-ready security configurations
	CORSOrigins           []string
	SessionTimeout        time.Duration
	MaxLoginAttempts      int
	RateLimitRequests     int
	RateLimitWindow       time.Duration
	EnableSecurityHeaders bool
	EnableAuditLogging    bool
	JWTRefreshEnabled     bool
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
func loadConfig() *Config {
	addr := getEnv("LISTEN_ADDR", ":8080")
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// Don't set a default in production
		if getEnv("ENVIRONMENT", "development") == "production" {
			log.Fatal("JWT_SECRET must be set in production")
		}
		log.Println("Warning: Using default JWT_SECRET for development")
		secret = "ca1493f9b638c47219bb82db9843a086"
	}

	ptSec := getEnv("PROOF_TIMEOUTSEC", "5")
	pt, err := time.ParseDuration(ptSec + "s")
	if err != nil {
		log.Printf("invalid PROOF_TIMEOUTSEC, defaulting to 5s")
		pt = 5 * time.Second
	}

	// Phase 1: Enhanced configuration
	environment := getEnv("ENVIRONMENT", "development")
	databaseURL := getEnv("DATABASE_URL", "vault.db")
	enableHTTPS := getEnv("ENABLE_HTTPS", "false") == "true"
	logLevel := getEnv("LOG_LEVEL", "info")

	// Parse trusted proxies
	var trustedProxies []string
	if proxies := os.Getenv("TRUSTED_PROXIES"); proxies != "" {
		trustedProxies = strings.Split(proxies, ",")
		for i, proxy := range trustedProxies {
			trustedProxies[i] = strings.TrimSpace(proxy)
		}
	}

	// Production-ready security configurations
	corsOrigins := strings.Split(getEnv("CORS_ORIGINS", "*"), ",")
	var sessionTimeout time.Duration
	if st, err := time.ParseDuration(getEnv("SESSION_TIMEOUT", "3600s")); err == nil {
		sessionTimeout = st
	} else {
		sessionTimeout = 3600 * time.Second
	}
	maxLoginAttempts := getEnvAsInt("MAX_LOGIN_ATTEMPTS", 5)
	rateLimitRequests := getEnvAsInt("RATE_LIMIT_REQUESTS", 100)
	rateLimitWindow := getEnvAsDuration("RATE_LIMIT_WINDOW", "1m")
	enableSecurityHeaders := getEnv("ENABLE_SECURITY_HEADERS", "true") == "true"
	enableAuditLogging := getEnv("ENABLE_AUDIT_LOGGING", "false") == "true"
	jwtRefreshEnabled := getEnv("JWT_REFRESH_ENABLED", "true") == "true"

	passwordPolicy := PasswordPolicyConfig{
		MinLength:      getEnvAsInt("PASSWORD_MIN_LENGTH", 8),
		RequireUpper:   getEnv("PASSWORD_REQUIRE_UPPER", "true") == "true",
		RequireLower:   getEnv("PASSWORD_REQUIRE_LOWER", "true") == "true",
		RequireDigit:   getEnv("PASSWORD_REQUIRE_DIGIT", "true") == "true",
		RequireSpecial: getEnv("PASSWORD_REQUIRE_SPECIAL", "true") == "true",
		MaxAge:         getEnvAsDuration("PASSWORD_MAX_AGE", "90d"),
	}

	return &Config{
		Addr:                  addr,
		PasetoSecret:          []byte(secret),
		ProofTimeout:          pt,
		Environment:           environment,
		DatabaseURL:           databaseURL,
		EnableHTTPS:           enableHTTPS,
		TrustedProxies:        trustedProxies,
		LogLevel:              logLevel,
		CORSOrigins:           corsOrigins,
		SessionTimeout:        sessionTimeout,
		MaxLoginAttempts:      maxLoginAttempts,
		RateLimitRequests:     rateLimitRequests,
		RateLimitWindow:       rateLimitWindow,
		EnableSecurityHeaders: enableSecurityHeaders,
		EnableAuditLogging:    enableAuditLogging,
		JWTRefreshEnabled:     jwtRefreshEnabled,
		PasswordPolicy:        passwordPolicy,
	}
}

func parseIntWithDefault(envKey string, defaultValue int) int {
	valueStr := os.Getenv(envKey)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		log.Printf("invalid %s value '%s', using default %d", envKey, valueStr, defaultValue)
		return defaultValue
	}
	return value
}

func parseDurationWithDefault(envKey, defaultValue string) time.Duration {
	valueStr := os.Getenv(envKey)
	if valueStr == "" {
		valueStr = defaultValue
	}
	duration, err := time.ParseDuration(valueStr)
	if err != nil {
		defaultDuration, _ := time.ParseDuration(defaultValue)
		log.Printf("invalid %s value '%s', using default %s", envKey, valueStr, defaultValue)
		return defaultDuration
	}
	return duration
}

func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

func getEnvAsDuration(key, defaultValue string) time.Duration {
	valueStr := getEnv(key, defaultValue)
	value, err := time.ParseDuration(valueStr)
	if err != nil {
		return 0
	}
	return value
}
