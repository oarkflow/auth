package pkg

import (
	"fmt"
	"net/http"
	"strings"
)

// --- MFA Handlers ---

// mfaSetupHandler handles MFA setup for authenticated users
func mfaSetupHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pubHex, _ := r.Context().Value("user").(string)
		userInfo, exists := lookupUserByPubHex(pubHex)
		if !exists {
			renderErrorPage(w, http.StatusNotFound, "User Not Found",
				"User information could not be retrieved.",
				"Please log in again.", "User not found during MFA setup", "/login")
			return
		}

		if r.Method == "GET" {
			// Check if MFA is already enabled
			mfaEnabled, _ := manager.Vault.IsUserMFAEnabled(userInfo.UserID)
			if mfaEnabled {
				renderErrorPage(w, http.StatusBadRequest, "MFA Already Enabled",
					"Multi-Factor Authentication is already enabled for your account.",
					"You can disable MFA first if you want to set it up again.", "", "/protected")
				return
			}

			// Generate new MFA secret and QR code
			secret, qrCode, err := GenerateMFASecret(userInfo.Username, "Auth System")
			if err != nil {
				renderErrorPage(w, http.StatusInternalServerError, "MFA Setup Error",
					"Failed to generate MFA credentials.",
					"Please try again later.", fmt.Sprintf("MFA generation error: %v", err), "/protected")
				return
			}

			// Generate backup codes
			backupCodes, err := GenerateBackupCodes(10)
			if err != nil {
				renderErrorPage(w, http.StatusInternalServerError, "Backup Codes Error",
					"Failed to generate backup codes.",
					"Please try again later.", fmt.Sprintf("Backup codes error: %v", err), "/protected")
				return
			}

			// Store in session temporarily (not in database yet)
			setSessionData(w, "mfa_temp_secret", secret)
			setSessionData(w, "mfa_temp_backup_codes", strings.Join(backupCodes, ","))
			qrCode = strings.ReplaceAll(qrCode, "data:image/png;base64,", "")
			data := MFASetupData{
				Secret:      secret,
				QRCode:      qrCode,
				BackupCodes: backupCodes,
			}

			manager.renderTemplate(w, "mfa-setup.html", data)
			return
		}

		if r.Method == "POST" {
			// Verify the TOTP code before enabling MFA
			code := r.FormValue("code")
			if code == "" {
				renderErrorPage(w, http.StatusBadRequest, "Verification Code Required",
					"Please enter the verification code from your authenticator app.",
					"", "", "/mfa/setup")
				return
			}

			// Get temporary secret from session
			tempSecret, exists := getSessionData(r, "mfa_temp_secret")
			if !exists || tempSecret == "" {
				renderErrorPage(w, http.StatusBadRequest, "Setup Session Expired",
					"MFA setup session has expired.",
					"Please start the setup process again.", "", "/mfa/setup")
				return
			}

			// Verify the code
			if !VerifyMFACode(code, tempSecret) {
				renderErrorPage(w, http.StatusBadRequest, "Invalid Verification Code",
					"The verification code is incorrect.",
					"Please check your authenticator app and try again.", "", "/mfa/setup")
				return
			}

			// Get backup codes from session
			tempBackupCodesStr, _ := getSessionData(r, "mfa_temp_backup_codes")
			backupCodes := strings.Split(tempBackupCodesStr, ",")

			// Save MFA settings to database
			err := manager.Vault.SetUserMFA(userInfo.UserID, tempSecret, backupCodes)
			if err != nil {
				renderErrorPage(w, http.StatusInternalServerError, "Database Error",
					"Failed to save MFA settings.",
					"Please try again later.", fmt.Sprintf("MFA save error: %v", err), "/protected")
				return
			}

			// Enable MFA for the user
			err = manager.Vault.EnableMFA(userInfo.UserID)
			if err != nil {
				renderErrorPage(w, http.StatusInternalServerError, "MFA Enable Error",
					"Failed to enable MFA for your account.",
					"Please try again later.", fmt.Sprintf("MFA enable error: %v", err), "/protected")
				return
			}

			// Clear session data
			clearSessionData(w, "mfa_temp_secret")
			clearSessionData(w, "mfa_temp_backup_codes")

			manager.renderTemplate(w, "mfa-enabled.html", nil)
		}
	}
}

// mfaVerifyHandler handles MFA code verification during login
func mfaVerifyHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			manager.renderTemplate(w, "mfa-verify.html", nil)
			return
		}

		if r.Method == "POST" {
			username := r.FormValue("username")
			code := r.FormValue("code")

			if username == "" || code == "" {
				manager.renderTemplate(w, "mfa-verify.html", map[string]any{
					"Username": username,
					"Error":    "Username and code are required",
				})
				return
			}

			userInfo, exists := lookupUserByUsername(username)
			if !exists {
				manager.renderTemplate(w, "mfa-verify.html", map[string]any{
					"Username": username,
					"Error":    "User not found",
				})
				return
			}

			mfaEnabled, err := manager.Vault.IsUserMFAEnabled(userInfo.UserID)
			if err != nil || !mfaEnabled {
				manager.renderTemplate(w, "mfa-verify.html", map[string]any{
					"Username": username,
					"Error":    "MFA not enabled for this user",
				})
				return
			}

			secret, backupCodes, err := manager.Vault.GetUserMFA(userInfo.UserID)
			if err != nil {
				manager.renderTemplate(w, "mfa-verify.html", map[string]any{
					"Username": username,
					"Error":    "Failed to retrieve MFA settings",
				})
				return
			}

			isValid := false
			if len(code) == 6 {
				isValid = VerifyMFACode(code, secret)
			} else if IsBackupCodeFormat(code) {
				formattedCode := FormatBackupCode(code)
				for _, backupCode := range backupCodes {
					if backupCode == formattedCode {
						isValid = true
						manager.Vault.InvalidateBackupCode(userInfo.UserID, formattedCode)
						break
					}
				}
			}

			if !isValid {
				clientIP := getClientIP(r)
				manager.Security.RecordFailedLogin(clientIP)
				manager.renderTemplate(w, "mfa-verify.html", map[string]any{
					"Username": username,
					"Error":    "Invalid MFA code",
				})
				return
			}

			// Based on user's login type, show appropriate login form
			if userInfo.LoginType == "simple" {
				// Show simple login form with just password
				manager.renderTemplate(w, "simple-login.html", map[string]any{
					"Username": username,
					"UserInfo": userInfo,
				})
			} else {
				// Show secured login form
				manager.renderTemplate(w, "secured-login.html", map[string]any{
					"Username": username,
					"UserInfo": userInfo,
				})
			}
		}
	}
}

// mfaDisableHandler handles MFA disabling for authenticated users
func mfaDisableHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pubHex, _ := r.Context().Value("user").(string)
		info, _ := lookupUserByPubHex(pubHex)

		userInfo, exists := lookupUserByUsername(info.Username)
		if !exists {
			renderErrorPage(w, http.StatusNotFound, "User Not Found",
				"User information could not be retrieved.",
				"Please log in again.", "User not found during MFA disable", "/login")
			return
		}

		if r.Method == "POST" {
			// Verify current password or MFA code before disabling
			password := r.FormValue("password")
			if password == "" {
				renderErrorPage(w, http.StatusBadRequest, "Password Required",
					"Please enter your current password to disable MFA.",
					"", "", "/protected")
				return
			}

			// Verify password
			storedSecret, err := manager.Vault.GetUserSecret(userInfo.UserID)
			if err != nil || !verifyPassword(password, storedSecret) {
				renderErrorPage(w, http.StatusUnauthorized, "Invalid Password",
					"The password you entered is incorrect.",
					"Please try again.", "", "/protected")
				return
			}

			// Disable MFA
			err = manager.Vault.DisableMFA(userInfo.UserID)
			if err != nil {
				renderErrorPage(w, http.StatusInternalServerError, "MFA Disable Error",
					"Failed to disable MFA for your account.",
					"Please try again later.", fmt.Sprintf("MFA disable error: %v", err), "/protected")
				return
			}

			manager.renderTemplate(w, "mfa-disabled.html", nil)
		}
	}
}

// mfaBackupCodesHandler handles regenerating backup codes
func mfaBackupCodesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pubHex, _ := r.Context().Value("user").(string)
		info, _ := lookupUserByPubHex(pubHex)

		userInfo, exists := lookupUserByUsername(info.Username)
		if !exists {
			renderErrorPage(w, http.StatusNotFound, "User Not Found",
				"User information could not be retrieved.",
				"Please log in again.", "User not found during backup codes generation", "/login")
			return
		}

		// Check if MFA is enabled
		mfaEnabled, err := manager.Vault.IsUserMFAEnabled(userInfo.UserID)
		if err != nil || !mfaEnabled {
			renderErrorPage(w, http.StatusBadRequest, "MFA Not Enabled",
				"Multi-Factor Authentication is not enabled for your account.",
				"Please enable MFA first.", "", "/protected")
			return
		}

		if r.Method == "POST" {
			// Generate new backup codes
			backupCodes, err := GenerateBackupCodes(10)
			if err != nil {
				renderErrorPage(w, http.StatusInternalServerError, "Backup Codes Error",
					"Failed to generate new backup codes.",
					"Please try again later.", fmt.Sprintf("Backup codes error: %v", err), "/protected")
				return
			}

			// Get current MFA secret
			secret, _, err := manager.Vault.GetUserMFA(userInfo.UserID)
			if err != nil {
				renderErrorPage(w, http.StatusInternalServerError, "MFA Settings Error",
					"Failed to retrieve MFA settings.",
					"Please try again later.", fmt.Sprintf("MFA get error: %v", err), "/protected")
				return
			}

			// Update with new backup codes
			err = manager.Vault.SetUserMFA(userInfo.UserID, secret, backupCodes)
			if err != nil {
				renderErrorPage(w, http.StatusInternalServerError, "Database Error",
					"Failed to save new backup codes.",
					"Please try again later.", fmt.Sprintf("Backup codes save error: %v", err), "/protected")
				return
			}

			manager.renderTemplate(w, "mfa-backup-codes.html", map[string]interface{}{
				"BackupCodes": backupCodes,
			})
		}
	}
}
