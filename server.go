package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	expDuration           = 15 * time.Minute
	nonceCleanupSec       = 60
	maxLoginAttempts      = 5
	loginCooldownPeriod   = 15 * time.Minute
	maxRequestsPerMin     = 30
	passwordMinLength     = 8
	passwordResetTokenExp = 30 * time.Minute
)

func main() {
	manager = NewManager()
	srv := &http.Server{
		Addr:         manager.Config.Addr,
		Handler:      setupRoutes(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	startServer(srv)
}

func setupRoutes() http.Handler {
	mux := http.NewServeMux()

	// Authentication routes
	mux.Handle("/", rateLimitMiddleware(http.HandlerFunc(homeHandler)))
	mux.Handle("/health", rateLimitMiddleware(http.HandlerFunc(health)))
	mux.Handle("/nonce", rateLimitMiddleware(http.HandlerFunc(nonce)))
	mux.Handle("/register", rateLimitMiddleware(http.HandlerFunc(register)))
	mux.Handle("/verify", rateLimitMiddleware(http.HandlerFunc(verifyHandler)))
	mux.Handle("/login", rateLimitMiddleware(http.HandlerFunc(loginSelectionHandler)))
	mux.Handle("/simple-login", rateLimitMiddleware(loginProtectionMiddleware(http.HandlerFunc(simpleLoginHandler(manager.Config)))))
	mux.Handle("/secured-login", rateLimitMiddleware(loginProtectionMiddleware(http.HandlerFunc(securedLoginHandler(manager.Config)))))
	mux.Handle("/logout", rateLimitMiddleware(http.HandlerFunc(logoutHandler(manager.Config))))
	mux.Handle("/sso", rateLimitMiddleware(http.HandlerFunc(ssoHandler(manager.Config))))
	mux.Handle("/forgot-password", rateLimitMiddleware(http.HandlerFunc(forgotPasswordHandler)))
	mux.Handle("/reset-password", rateLimitMiddleware(http.HandlerFunc(resetPasswordHandler)))
	mux.Handle("/protected", pasetoMiddleware(manager.Config, protectedHandler()))

	// OAuth 2.0 Authorization Server endpoints
	mux.Handle("/oauth/authorize", rateLimitMiddleware(http.HandlerFunc(oauthAuthorizeHandler(manager.Config))))
	mux.Handle("/oauth/consent", rateLimitMiddleware(http.HandlerFunc(oauthConsentHandler(manager.Config))))
	mux.Handle("/oauth/token", rateLimitMiddleware(http.HandlerFunc(oauthTokenHandler(manager.Config))))
	mux.Handle("/oauth/userinfo", rateLimitMiddleware(http.HandlerFunc(oauthUserInfoHandler(manager.Config))))
	mux.Handle("/oauth/clients/register", rateLimitMiddleware(http.HandlerFunc(clientRegistrationHandler(manager.Config))))

	// API endpoints
	mux.Handle("/api/status", rateLimitMiddleware(http.HandlerFunc(apiStatusHandler)))
	mux.Handle("/api/userinfo", pasetoMiddleware(manager.Config, http.HandlerFunc(apiUserInfoHandler(manager.Config))))
	mux.Handle("/api/login", rateLimitMiddleware(loginProtectionMiddleware(http.HandlerFunc(apiSimpleLoginHandler(manager.Config)))))
	mux.Handle("/api-demo", rateLimitMiddleware(http.HandlerFunc(apiDemoHandler)))

	// Static files serving
	fs := http.FileServer(http.Dir("static/"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Apply middleware chain to the mux
	var handler http.Handler = mux

	// Security and logging middleware (outermost)
	handler = securityHeadersMiddleware(handler)
	handler = corsMiddleware(handler)
	handler = auditLoggingMiddleware(handler)
	handler = requestValidationMiddleware(handler)
	handler = sessionTimeoutMiddleware(manager.Config, handler)

	return handler
}

func startServer(srv *http.Server) {
	go func() {
		log.Printf("▶ listening on http://localhost%s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("⏳ shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	log.Println("✔ shutdown complete")
}
