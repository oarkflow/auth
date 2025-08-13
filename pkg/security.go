package pkg

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SecurityHeadersMiddleware adds production-ready security headers
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if manager.Config.EnableSecurityHeaders {
			// Security headers for production
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

			// Content Security Policy
			csp := "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; img-src 'self' data:; font-src 'self'; connect-src 'self'"
			w.Header().Set("Content-Security-Policy", csp)

			// HSTS header for HTTPS
			if manager.Config.EnableHTTPS {
				w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Enhanced CORS middleware with configurable origins
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range manager.Config.CORSOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
		}

		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT,DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Access-Control-Allow-Headers, Origin,Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Audit logging middleware
func auditLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !manager.Config.EnableAuditLogging {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		clientIP := getClientIP(r)
		userAgent := r.Header.Get("User-Agent")

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}

		next.ServeHTTP(wrapped, r)

		// Log the request
		duration := time.Since(start)
		logAuditEvent(AuditLog{
			Timestamp:  start,
			Method:     r.Method,
			Path:       r.URL.Path,
			StatusCode: wrapped.statusCode,
			Duration:   duration,
			ClientIP:   clientIP,
			UserAgent:  userAgent,
			UserID:     getUserIDFromContext(r.Context()),
		})
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

type AuditLog struct {
	Timestamp  time.Time     `json:"timestamp"`
	Method     string        `json:"method"`
	Path       string        `json:"path"`
	StatusCode int           `json:"status_code"`
	Duration   time.Duration `json:"duration"`
	ClientIP   string        `json:"client_ip"`
	UserAgent  string        `json:"user_agent"`
	UserID     string        `json:"user_id,omitempty"`
}

func logAuditEvent(log AuditLog) {
	// In production, you might want to send this to a logging service
	fmt.Printf("[AUDIT] %s %s %s - %d (%v) - IP: %s - User: %s\n",
		log.Timestamp.Format("2006-01-02 15:04:05"),
		log.Method,
		log.Path,
		log.StatusCode,
		log.Duration,
		log.ClientIP,
		log.UserID,
	)
}

func getUserIDFromContext(ctx context.Context) string {
	if userVal := ctx.Value("user"); userVal != nil {
		if pubHex, ok := userVal.(string); ok {
			if info, exists := lookupUserByPubHex(pubHex); exists {
				return info.UserID
			}
		}
	}
	return ""
}

// Enhanced request validation middleware
func requestValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for common attack patterns
		if containsSuspiciousPatterns(r.URL.Path) {
			renderErrorPage(w, http.StatusBadRequest, "Invalid Request",
				"The request contains invalid characters.",
				"Please check your request and try again.",
				"Suspicious patterns detected in request path", "/")
			return
		}

		// Limit request body size (10MB)
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

		// Check content type for POST requests
		if r.Method == "POST" {
			contentType := r.Header.Get("Content-Type")
			if !strings.Contains(contentType, "application/json") &&
				!strings.Contains(contentType, "application/x-www-form-urlencoded") &&
				!strings.Contains(contentType, "multipart/form-data") {
				renderErrorPage(w, http.StatusBadRequest, "Invalid Content Type",
					"Unsupported content type for POST request.",
					"Please use application/json, application/x-www-form-urlencoded, or multipart/form-data.",
					fmt.Sprintf("Unsupported content type: %s", contentType), "/")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func containsSuspiciousPatterns(path string) bool {
	suspicious := []string{
		"../", "..\\", ".env", "/etc/", "/proc/", "/sys/",
		"<script", "javascript:", "vbscript:", "data:",
		"union select", "drop table", "truncate", "delete from",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range suspicious {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// Session timeout middleware
func sessionTimeoutMiddleware(cfg *Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip for public endpoints
		if isPublicEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		tokenStr := ""
		cookie, err := r.Cookie("session_token")
		if err == nil {
			tokenStr = cookie.Value
		} else if r.Header.Get("Authorization") != "" {
			auth := r.Header.Get("Authorization")
			if len(auth) > 7 && auth[:7] == "Bearer " {
				tokenStr = auth[7:]
			}
		}

		if tokenStr != "" {
			// Check token expiration against session timeout
			// This would be implemented with token validation
		}

		next.ServeHTTP(w, r)
	})
}

func isPublicEndpoint(path string) bool {
	publicEndpoints := []string{
		"/", "/health", "/nonce", "/register", "/verify",
		"/login", "/simple-login", "/secured-login",
		"/forgot-password", "/reset-password", "/api/status",
	}

	for _, endpoint := range publicEndpoints {
		if path == endpoint || strings.HasPrefix(path, "/static/") {
			return true
		}
	}
	return false
}
