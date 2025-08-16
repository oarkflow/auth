package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/auth/pkg/http/requests"
	"github.com/oarkflow/auth/pkg/http/responses"
	"github.com/oarkflow/auth/pkg/libs"
	"github.com/oarkflow/auth/pkg/models"
	"github.com/oarkflow/auth/pkg/objects"
	"github.com/oarkflow/auth/pkg/utils"
)

func MFASetupPage(c *fiber.Ctx) error {
	userInfo, _ := c.Locals("userInfo").(models.UserInfo)
	// Check if MFA is already enabled
	mfaEnabled, _ := objects.Manager.Vault().IsUserMFAEnabled(userInfo.UserID)
	if mfaEnabled {
		return renderErrorPage(c, http.StatusBadRequest, "MFA Already Enabled",
			"Multi-Factor Authentication is already enabled for your account.",
			"You can disable MFA first if you want to set it up again.", "", utils.AppURI)
	}

	// Generate new MFA secret and QR code
	secret, qrCode, err := libs.GenerateMFASecret(userInfo.Username, "Auth System")
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "MFA Setup Error",
			"Failed to generate MFA credentials.",
			"Please try again later.", fmt.Sprintf("MFA generation error: %v", err), utils.AppURI)
	}

	// Generate backup codes
	backupCodes, err := libs.GenerateBackupCodes(10)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Backup Codes Error",
			"Failed to generate backup codes.",
			"Please try again later.", fmt.Sprintf("Backup codes error: %v", err), utils.AppURI)
	}

	// Store in session temporarily (not in database yet)
	setSessionData(c, "mfa_temp_secret", secret)
	setSessionData(c, "mfa_temp_backup_codes", strings.Join(backupCodes, ","))
	qrCode = strings.ReplaceAll(qrCode, "data:image/png;base64,", "")
	data := models.MFASetupData{
		Secret:      secret,
		QRCode:      qrCode,
		BackupCodes: backupCodes,
	}
	return responses.Render(c, utils.MFASetupTemplate, data)
}

func MFAVerifyPage(c *fiber.Ctx) error {
	return responses.Render(c, utils.MFAVerifyTemplate, fiber.Map{
		"Title": "MFA Verify",
	})
}

func MFABackupCodesPage(c *fiber.Ctx) error {
	userInfo, _ := c.Locals("userInfo").(models.UserInfo)
	if !userInfo.MFAEnabled {
		return renderErrorPage(c, http.StatusBadRequest, "MFA Not Enabled",
			"Multi-Factor Authentication is not enabled for your account.",
			"You need to enable MFA first.", "", utils.AppURI)
	}
	// Generate new backup codes
	backupCodes, err := libs.GenerateBackupCodes(10)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Backup Codes Error",
			"Failed to generate new backup codes.",
			"Please try again later.", fmt.Sprintf("Backup codes error: %v", err), utils.AppURI)
	}

	// Get current MFA secret
	secret, _, err := objects.Manager.Vault().GetUserMFA(userInfo.UserID)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "MFA Settings Error",
			"Failed to retrieve MFA settings.",
			"Please try again later.", fmt.Sprintf("MFA get error: %v", err), utils.AppURI)
	}

	// Update with new backup codes
	err = objects.Manager.Vault().SetUserMFA(userInfo.UserID, secret, backupCodes)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Database Error",
			"Failed to save new backup codes.",
			"Please try again later.", fmt.Sprintf("Backup codes save error: %v", err), utils.AppURI)
	}
	return responses.Render(c, utils.MFABackupCodesTemplate, fiber.Map{
		"Title":       "MFA Backup Codes",
		"BackupCodes": backupCodes,
	})
}

func PostMFASetup(c *fiber.Ctx) error {
	userInfo, _ := c.Locals("userInfo").(models.UserInfo)
	var req requests.MFASetupRequest
	if err := c.BodyParser(&req); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Verification Code Required",
			"Please enter the verification code from your authenticator app.",
			"", "", utils.MFASetupURI)
	}
	if req.Code == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Verification Code Required",
			"Please enter the verification code from your authenticator app.",
			"", "", utils.MFASetupURI)
	}
	// Get temporary secret from session
	tempSecret, exists := getSessionData(c, "mfa_temp_secret")
	if !exists || tempSecret == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Setup Session Expired",
			"MFA setup session has expired.",
			"Please start the setup process again.", "", utils.MFASetupURI)
	}

	// Verify the code
	if !libs.VerifyMFACode(req.Code, tempSecret) {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Verification Code",
			"The verification code is incorrect.",
			"Please check your authenticator app and try again.", "", utils.MFASetupURI)
	}

	// Get backup codes from session
	tempBackupCodesStr, _ := getSessionData(c, "mfa_temp_backup_codes")
	backupCodes := strings.Split(tempBackupCodesStr, ",")

	// Save MFA settings to database
	err := objects.Manager.Vault().SetUserMFA(userInfo.UserID, tempSecret, backupCodes)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Database Error",
			"Failed to save MFA settings.",
			"Please try again later.", fmt.Sprintf("MFA save error: %v", err), utils.AppURI)
	}

	// Enable MFA for the user
	err = objects.Manager.Vault().EnableMFA(userInfo.UserID)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "MFA Enable Error",
			"Failed to enable MFA for your account.",
			"Please try again later.", fmt.Sprintf("MFA enable error: %v", err), utils.AppURI)
	}

	// Clear session data
	clearSessionData(c, "mfa_temp_secret")
	clearSessionData(c, "mfa_temp_backup_codes")
	return responses.Render(c, utils.MFAEnabledTemplate, fiber.Map{
		"Title": "MFA Enabled",
	})
}

func PostMFAVerify(c *fiber.Ctx) error {
	var req requests.MFARequest
	if err := c.BodyParser(&req); err != nil {
		return responses.Render(c, utils.MFAVerifyTemplate, fiber.Map{
			"Error": "Unable to parse request data",
		})
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	code := req.Code
	if username == "" {
		return responses.Render(c, utils.MFAVerifyTemplate, fiber.Map{
			"Username": username,
			"Error":    "Username and code are required",
		})
	}
	userInfo, hasUser := objects.Manager.LookupUserByUsername(username)
	if !hasUser {
		return responses.Render(c, utils.MFAVerifyTemplate, fiber.Map{
			"Username": username,
			"Error":    "User not found",
		})
	}
	if !userInfo.MFAEnabled {
		return responses.Render(c, utils.MFAVerifyTemplate, fiber.Map{
			"Username": username,
			"Error":    "MFA not enabled for this user",
		})
	}
	secret, backupCodes, err := objects.Manager.Vault().GetUserMFA(userInfo.UserID)
	if err != nil {
		return responses.Render(c, utils.MFAVerifyTemplate, fiber.Map{
			"Username": username,
			"Error":    "Failed to retrieve MFA settings",
		})
	}
	isValid := false
	if len(code) == 6 {
		isValid = libs.VerifyMFACode(code, secret)
	} else if libs.IsBackupCodeFormat(code) {
		formattedCode := libs.FormatBackupCode(code)
		for _, backupCode := range backupCodes {
			if backupCode == formattedCode {
				isValid = true
				objects.Manager.Vault().InvalidateBackupCode(userInfo.UserID, formattedCode)
				break
			}
		}
	}

	if !isValid {
		clientIP := utils.GetClientIP(c)
		objects.Manager.Security().RecordFailedLogin(clientIP)
		return responses.Render(c, utils.MFAVerifyTemplate, fiber.Map{
			"Username": username,
			"UserInfo": userInfo,
			"Error":    "Invalid MFA code. Please try again.",
		})
	}

	// Based on user's login type, show appropriate login form
	if userInfo.LoginType == "simple" {
		return responses.Render(c, utils.SimpleLoginTemplate, fiber.Map{
			"Username": username,
			"UserInfo": userInfo,
		})
	}
	return responses.Render(c, utils.SecuredLoginTemplate, fiber.Map{
		"Username": username,
		"UserInfo": userInfo,
	})
}

func PostMFADisable(c *fiber.Ctx) error {
	userInfo, _ := c.Locals("userInfo").(models.UserInfo)
	var req requests.MFADisableRequest
	if err := c.BodyParser(&req); err != nil {
		return responses.Render(c, utils.MFAVerifyTemplate, fiber.Map{
			"Error": "Unable to parse request data",
		})
	}
	// Verify current password or MFA code before disabling
	password := req.Password
	if password == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Password Required",
			"Please enter your current password to disable MFA.",
			"", "", utils.AppURI)
	}

	// Verify password
	storedSecret, err := objects.Manager.Vault().GetUserSecret(userInfo.UserID)
	if err != nil {
		return renderErrorPage(c, http.StatusUnauthorized, "Invalid Password",
			"The password you entered is incorrect.",
			"Please try again.", "", utils.LoginURI)
	}
	ok, err := verifyPassword(password, storedSecret)
	if !ok || err != nil {
		return renderErrorPage(c, http.StatusUnauthorized, "Invalid Password",
			"The password you entered is incorrect.",
			"Please try again.", "", utils.LoginURI)
	}

	// Disable MFA
	err = objects.Manager.Vault().DisableMFA(userInfo.UserID)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "MFA Disable Error",
			"Failed to disable MFA for your account.",
			"Please try again later.", fmt.Sprintf("MFA disable error: %v", err), utils.AppURI)
	}
	return responses.Render(c, utils.MFADisabledTemplate, nil)
}
