package main

import (
	"log"
	"os"
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

	return &Config{
		Addr:           addr,
		PasetoSecret:   []byte(secret),
		ProofTimeout:   pt,
		Environment:    environment,
		DatabaseURL:    databaseURL,
		EnableHTTPS:    enableHTTPS,
		TrustedProxies: trustedProxies,
		LogLevel:       logLevel,
	}
}

func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
