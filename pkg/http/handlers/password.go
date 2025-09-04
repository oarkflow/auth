package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/auth/pkg/http/requests"
	"github.com/oarkflow/auth/pkg/http/responses"
	"github.com/oarkflow/auth/pkg/libs"
	"github.com/oarkflow/auth/pkg/models"
	"github.com/oarkflow/auth/pkg/objects"
	"github.com/oarkflow/auth/pkg/utils"
	"github.com/oarkflow/hash"
)

func PasswordResetPage(c *fiber.Ctx) error {
	token := c.Query("token")
	resetData, valid := objects.Manager.ValidatePasswordResetToken(token)
	if !valid {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid or Expired Reset Token",
			"This password reset link is invalid or has expired.",
			"Please request a new password reset link.",
			"Invalid or expired reset token", "/forgot-password")
	}
	return responses.Render(c, utils.PasswordResetTemplate, map[string]any{
		"Token":    token,
		"Username": resetData.Username,
	})
}

func ForgotPasswordPage(c *fiber.Ctx) error {
	return responses.Render(c, utils.ForgotPasswordTemplate, fiber.Map{
		"Title": "Forgot Password",
	})
}

func PostResetPassword(c *fiber.Ctx) error {
	var req requests.ResetPasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Form Data",
			"The form data could not be processed.",
			"Please check your input and try again.",
			fmt.Sprintf("ParseForm error: %v", err), utils.ForgotPasswordURI)
	}
	token := req.Token
	newPassword := req.Password
	confirmPassword := req.ConfirmPassword
	if token == "" || newPassword == "" || confirmPassword == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Required Information",
			"All fields are required for password reset.",
			"Please provide the token, new password, and password confirmation.",
			"Missing required fields", "/forgot-password")
	}

	if newPassword != confirmPassword {
		return renderErrorPage(c, http.StatusBadRequest, "Password Mismatch",
			"The passwords you entered do not match.",
			"Please ensure both password fields contain the same value.",
			"Password confirmation mismatch", c.Path())
	}

	// Validate new password strength
	if err := utils.ValidatePassword(newPassword); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Weak Password",
			"Your new password does not meet the security requirements.",
			err.Error(),
			err.Error(), c.Path())
	}
	// Validate and consume reset token
	resetData, valid := objects.Manager.ValidatePasswordResetToken(token)
	if !valid {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid or Expired Reset Token",
			"This password reset token is invalid or has expired.",
			"Please request a new password reset link.",
			"Invalid or expired reset token", utils.ResetPasswordURI)
	}

	// --------------------------------------------------
	username := utils.SanitizeInput(strings.TrimSpace(resetData.Username))
	if username != resetData.Username {
		return renderErrorPage(c, http.StatusBadRequest, "Username Mismatch",
			"The username provided does not match the one associated with this reset token.",
			"Please ensure you are using the correct username.",
			"Username mismatch", c.Path())
	}
	password := req.Password
	multipartFile, err := c.FormFile("keyfile")
	if err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Key File",
			"No cryptographic key file was provided.",
			"Please select your .json key file that was downloaded during registration.",
			fmt.Sprintf("FormFile error: %v", err), utils.LoginURI)
	}
	file, err := multipartFile.Open()
	if err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Key File",
			"No cryptographic key file was provided.",
			"Please select your .json key file that was downloaded during registration.",
			fmt.Sprintf("FormFile error: %v", err), utils.LoginURI)
	}
	defer file.Close()

	var keyData map[string]string
	if err := json.NewDecoder(file).Decode(&keyData); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Key File Format",
			"The key file could not be read or is not in the correct format.",
			"Please ensure you're using the correct .json key file that was downloaded during registration.",
			fmt.Sprintf("JSON decode error: %v", err), utils.LoginURI)
	}
	pubx, ok1 := keyData["PubKeyX"]
	puby, ok2 := keyData["PubKeyY"]
	encPrivD, ok3 := keyData["EncryptedPrivateKeyD"]
	if !ok1 || !ok2 || !ok3 {
		return renderErrorPage(c, http.StatusBadRequest, "Incomplete Key File",
			"The key file is missing required cryptographic data.",
			"Please ensure you're using the complete, unmodified key file from registration.",
			"Missing PubKeyX, PubKeyY, or EncryptedPrivateKeyD fields", utils.LoginURI)
	}

	if password == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Password",
			"Password is required to decrypt your private key.",
			"Please enter the password you used during registration.",
			"Password field is empty", utils.LoginURI)
	}

	// Phase 1: Add rate limiting for secured login
	pubHex := pubx + ":" + puby

	info, exists := objects.Manager.LookupUserByPubHex(pubHex)
	if !exists {
		return renderErrorPage(c, http.StatusUnauthorized, "Unrecognized Key",
			"This cryptographic key is not associated with any registered user.",
			"Please check that you're using the correct key file, or register for a new account.",
			"Public key not found in user registry", utils.RegisterURI)
	}

	// Verify this matches the username provided
	if info.Username != username {
		return renderErrorPage(c, http.StatusUnauthorized, "Username/Key Mismatch",
			"The cryptographic key does not belong to the specified username.",
			"Please ensure you're using the correct key file for this account.",
			"Username does not match key owner", utils.LoginURI)
	}

	// Validate public key from credentials table
	storedPubX, storedPubY, err := objects.Manager.GetPublicKeyByUserID(info.UserID)
	if err != nil || storedPubX != pubx || storedPubY != puby {
		return renderErrorPage(c, http.StatusUnauthorized, "Key Validation Failed",
			"The cryptographic key does not match our stored credentials.",
			"There may be an issue with your key file or account. Please contact support.",
			"Public key mismatch with stored credentials", utils.LoginURI)
	}

	prevPasswordHash, err := objects.Manager.Vault().GetUserSecret(info.UserID)
	if err != nil {
		return renderErrorPage(c, http.StatusUnauthorized, "Account Verification Failed",
			"Could not verify your account password.",
			"There may be an issue with your account setup. Please contact support.",
			fmt.Sprintf("Password hash retrieval failed: %v", err), utils.LoginURI)
	}
	privd := utils.DecryptPrivateKeyD(encPrivD, prevPasswordHash)
	// --------------------------------------------------

	passwordHash, err := hash.Make(req.Password, objects.Config.GetString("auth.password_algo"))
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Password Processing Error",
			"Failed to securely process your password.",
			"Our system encountered an error while securing your password. Please try again.",
			fmt.Sprintf("bcrypt hash generation failed: %v", err), utils.RegisterURI)
	}
	if !objects.Manager.ConsumePasswordResetToken(token) {
		return renderErrorPage(c, http.StatusBadRequest, "Token Already Used",
			"This password reset token has already been used.",
			"Please request a new password reset link if needed.",
			"Reset token already consumed", utils.ResetPasswordURI)
	}
	loginType := info.LoginType
	userInfo := models.UserInfo{
		UserID:    info.UserID,
		Username:  info.Username,
		LoginType: loginType,
		PubHex:    pubHex,
	}
	objects.Manager.Vault().SetUserInfo(pubHex, userInfo)
	objects.Manager.Vault().SetUserPublicKey(info.UserID, libs.PadHex(pubx), libs.PadHex(puby))
	objects.Manager.RegisterUserKey(pubHex, []byte(pubx), []byte(puby))
	objects.Manager.Vault().SetUserSecret(info.UserID, passwordHash)

	// Invalidate cache for the updated user
	if manager, ok := objects.Manager.(*libs.Manager); ok {
		manager.InvalidateUserInfoCache(info.Username)
	}
	encPrivD = utils.EncryptPrivateKeyD(privd, passwordHash)
	keyData = map[string]string{
		"PubKeyX":              libs.PadHex(pubx),
		"PubKeyY":              libs.PadHex(puby),
		"EncryptedPrivateKeyD": encPrivD,
	}
	jsonData, _ := json.Marshal(keyData)

	userIDStr := fmt.Sprintf("%d", info.UserID)
	utils.LogAuditEvent(c, objects.Manager, &userIDStr, utils.AuditActionPasswordReset, nil, true, nil)

	return responses.Render(c, utils.PasswordResetSuccessTemplate, fiber.Map{
		"KeyJson": template.JS(jsonData),
	})
}

func PostForgotPassword(c *fiber.Ctx) error {
	var req requests.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Form Data",
			"The form data could not be processed.",
			"Please check your input and try again.",
			fmt.Sprintf("ParseForm error: %v", err), utils.ForgotPasswordURI)
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	if username == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Username",
			"Username is required to determine your login method.",
			"Please provide your username (email or phone number).",
			"Missing username field", utils.ForgotPasswordURI)
	}
	var validationErr error
	if utils.IsEmail(username) {
		validationErr = utils.ValidateEmail(username)
	} else if utils.IsPhone(username) {
		validationErr = utils.ValidatePhone(username)
	} else {
		validationErr = fmt.Errorf("username must be a valid email address or phone number")
	}
	if validationErr != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Username Format",
			"The username you provided is not valid.",
			validationErr.Error(),
			validationErr.Error(), utils.ForgotPasswordURI)
	}
	userInfo, hasUser := objects.Manager.LookupUserByUsername(username)
	if !hasUser {
		return renderErrorPage(c, http.StatusNotFound, "User Not Found",
			"No account found with that username.",
			"Please check your username or register for a new account.",
			fmt.Sprintf("Username '%s' not found", username), utils.RegisterURI)
	}
	if userInfo.MFAEnabled {
		return responses.Render(c, utils.MFAVerifyTemplate, fiber.Map{
			"Username": userInfo.Username,
		})
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Registration System Error",
			"Failed to generate verification token.",
			"Our system encountered an error while processing your registration. Please try again.",
			fmt.Sprintf("Random token generation failed: %v", err), utils.RegisterURI)
	}
	manager, ok := objects.Manager.(*libs.Manager)
	emailSender := utils.SendPasswordResetEmail
	smsSender := utils.SendPasswordResetSMS
	if ok {
		if manager.SendNotification.SendPasswordResetEmail != nil {
			emailSender = manager.SendNotification.SendPasswordResetEmail
		}
		if manager.SendNotification.SendPasswordResetSMS != nil {
			smsSender = manager.SendNotification.SendPasswordResetSMS
		}
	}
	tokenStr := hex.EncodeToString(tokenBytes)
	objects.Manager.SetPasswordResetToken(username, tokenStr)

	userIDStr := fmt.Sprintf("%d", userInfo.UserID)
	utils.LogAuditEvent(c, objects.Manager, &userIDStr, utils.AuditActionPasswordReset, nil, true, nil)

	if utils.IsPhone(username) {
		smsSender(c, username, tokenStr)
		return responses.Render(c, utils.ForgotPasswordTemplate, fiber.Map{
			"Title":   "Password Reset Requested",
			"Message": "Password Reset Requested. Please check your phone for verification.",
			"Contact": username,
		})
	}
	emailSender(c, username, tokenStr)
	return responses.Render(c, utils.ForgotPasswordTemplate, fiber.Map{
		"Success": true,
		"Title":   "Password Reset Requested",
		"Message": "Password Reset Requested. Please check your email for verification.",
		"Contact": username,
	})
}
