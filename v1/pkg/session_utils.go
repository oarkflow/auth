package pkg

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// setSessionData stores temporary data in a session cookie (for MFA setup)
// Note: This is a simple implementation. In production, consider using secure session storage.
func setSessionData(w http.ResponseWriter, key, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "temp_" + key,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   600, // 10 minutes
	})
}

// getSessionData retrieves temporary data from session cookie
func getSessionData(r *http.Request, key string) (string, bool) {
	cookie, err := r.Cookie("temp_" + key)
	if err != nil {
		return "", false
	}
	return cookie.Value, true
}

// clearSessionData removes temporary session data
func clearSessionData(w http.ResponseWriter, key string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "temp_" + key,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Delete cookie
	})
}

// verifyPassword compares plaintext password with bcrypt hash
func verifyPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
