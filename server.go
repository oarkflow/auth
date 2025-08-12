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
	mux := setupRoutes()
	srv := &http.Server{
		Addr:         manager.Config.Addr,
		Handler:      cors(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	startServer(srv)
}

func setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()
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
	mux.Handle("/api/status", rateLimitMiddleware(http.HandlerFunc(apiStatusHandler)))
	mux.Handle("/api/userinfo", pasetoMiddleware(manager.Config, http.HandlerFunc(apiUserInfoHandler(manager.Config))))
	mux.Handle("/api/login", rateLimitMiddleware(loginProtectionMiddleware(http.HandlerFunc(apiSimpleLoginHandler(manager.Config)))))
	mux.Handle("/api-demo", rateLimitMiddleware(http.HandlerFunc(apiDemoHandler)))
	return mux
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
