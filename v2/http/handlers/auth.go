package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/paseto/token"
	"github.com/oarkflow/xid/wuid"
	"golang.org/x/crypto/bcrypt"

	v2 "github.com/oarkflow/auth/v2"
	"github.com/oarkflow/auth/v2/http/requests"
	"github.com/oarkflow/auth/v2/models"
	"github.com/oarkflow/auth/v2/objects"
	"github.com/oarkflow/auth/v2/utils"
)

const (
	expDuration         = 15 * time.Minute
	loginCooldownPeriod = 15 * time.Minute
)

func DashboardPage(c *fiber.Ctx) error {
	pubHex, _ := c.Locals("user").(string)
	info, _ := objects.Manager.LookupUserByPubHex(pubHex)
	return c.Render("protected", fiber.Map{
		"PubHex":   pubHex,
		"DBUserID": info.UserID,
		"Username": info.Username,
	})
}

func LandingPage(c *fiber.Ctx) error {
	return c.Render("index", fiber.Map{
		"Title": "Welcome to the Auth Service",
	})
}

func UserInfoPage(c *fiber.Ctx) error {
	pubHex, _ := c.Locals("user").(string)
	info, exists := objects.Manager.LookupUserByPubHex(pubHex)
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "user not found",
		})
	}

	// Get public key details
	pubKeyX, pubKeyY, err := objects.Manager.GetPublicKeyByUserID(info.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to retrieve user keys",
		})
	}

	// Get MFA status
	mfaEnabled, _ := objects.Manager.Vault.IsUserMFAEnabled(info.UserID)
	claims, ok := c.Locals("claims").(map[string]any)
	if !ok {
		claims = map[string]any{}
	}
	iat, _ := claims["iat"].(float64)
	exp_claim, _ := claims["exp"].(float64)

	return c.JSON(map[string]any{
		"authenticated": true,
		"user": map[string]any{
			"id":          info.UserID,
			"username":    info.Username,
			"login_type":  info.LoginType,
			"mfa_enabled": mfaEnabled,
			"pubKeyX":     pubKeyX,
			"pubKeyY":     pubKeyY,
			"pubHex":      pubHex,
		},
		"session": map[string]any{
			"issuedAt":  int64(iat),
			"expiresAt": int64(exp_claim),
			"timeLeft":  int64(exp_claim) - time.Now().Unix(),
		},
	})
}

func LogoutPage(c *fiber.Ctx) error {
	return c.Render("logout", fiber.Map{
		"Title": "Logout page",
	})
}

func VerifyPage(c *fiber.Ctx) error {
	var req requests.VerifyRequest
	if err := c.QueryParser(&req); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Form Data",
			"The verification form data could not be processed.",
			"Please check your input and try again.",
			fmt.Sprintf("ParseForm error: %v", err), "/register")
	}
	username := req.Username
	token := req.Token
	if username == "" || token == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Verification Link",
			"The verification link is missing required parameters.",
			"Please check that you clicked the complete link from your email or SMS, or try registering again.",
			"Missing username or token in verification URL", "/register")
	}
	if !objects.Manager.VerifyToken(username, token) {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Verification",
			"This verification link is either invalid or has already been used.",
			"The link may have expired or been used already. Please try registering again to get a new verification link.",
			"Verification token does not match or does not exist", "/register")
	}

	// Get login type preference
	loginType, err := objects.Manager.Vault.GetUserSecret(username + "_logintype")
	if err != nil {
		loginType = "simple" // default to simple
	}
	objects.Manager.Vault.SetUserSecret(username+"_logintype", "") // Remove temp

	// Generate key pair after verification
	pubx, puby, privd := v2.GenerateKeyPair()
	pubHex := v2.PadHex(pubx) + ":" + v2.PadHex(puby)
	info := models.UserInfo{
		UserID:    wuid.New().String(),
		Username:  username,
		LoginType: loginType,
	}
	objects.Manager.Vault.SetUserInfo(pubHex, info)
	// Store public key in credentials table
	objects.Manager.Vault.SetUserPublicKey(info.UserID, v2.PadHex(pubx), v2.PadHex(puby))
	objects.Manager.RegisterUserKey(pubHex, []byte(pubx), []byte(puby))
	// Retrieve password hash and move to DBUserID key
	passwordHash, err := objects.Manager.Vault.GetUserSecret(username)
	if err == nil {
		objects.Manager.Vault.SetUserSecret(info.UserID, passwordHash)
		objects.Manager.Vault.SetUserSecret(username, "") // Remove temp
	}
	// Retrieve plaintext password for encryption
	password, err := objects.Manager.Vault.GetUserSecret(username + "_plain")
	objects.Manager.Vault.SetUserSecret(username+"_plain", "") // Remove temp
	if err != nil || password == "" {
		return renderErrorPage(c, http.StatusInternalServerError, "Account Setup Error",
			"Failed to complete account setup due to missing password information.",
			"There was an issue finalizing your account. Please try registering again.",
			"Password not found for key encryption during verification", "/register")
	}
	if loginType == "simple" {
		return c.Redirect(LoginURI, http.StatusSeeOther)
	}
	encPrivD := utils.EncryptPrivateKeyD(privd, password)
	keyData := map[string]string{
		"PubKeyX":              v2.PadHex(pubx),
		"PubKeyY":              v2.PadHex(puby),
		"EncryptedPrivateKeyD": encPrivD,
	}
	jsonData, _ := json.Marshal(keyData)
	return c.Render("download-key-file", fiber.Map{
		"KeyJson": template.JS(jsonData),
	})
}

func LoginPage(c *fiber.Ctx) error {
	return c.Render("login", fiber.Map{
		"Title": "Login",
	})
}

func RegisterPage(c *fiber.Ctx) error {
	return c.Render("register", fiber.Map{
		"Title": "Register",
	})
}

func ForgotPasswordPage(c *fiber.Ctx) error {
	return c.Render("forgot-password", fiber.Map{
		"Title": "Forgot Password",
	})
}

func MFASetupPage(c *fiber.Ctx) error {
	pubHex, _ := c.Locals("user").(string)
	userInfo, exists := objects.Manager.LookupUserByPubHex(pubHex)
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "user not found",
		})
	}
	// Check if MFA is already enabled
	mfaEnabled, _ := objects.Manager.Vault.IsUserMFAEnabled(userInfo.UserID)
	if mfaEnabled {
		return renderErrorPage(c, http.StatusBadRequest, "MFA Already Enabled",
			"Multi-Factor Authentication is already enabled for your account.",
			"You can disable MFA first if you want to set it up again.", "", "/protected")
	}

	// Generate new MFA secret and QR code
	secret, qrCode, err := v2.GenerateMFASecret(userInfo.Username, "Auth System")
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "MFA Setup Error",
			"Failed to generate MFA credentials.",
			"Please try again later.", fmt.Sprintf("MFA generation error: %v", err), "/protected")
	}

	// Generate backup codes
	backupCodes, err := v2.GenerateBackupCodes(10)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Backup Codes Error",
			"Failed to generate backup codes.",
			"Please try again later.", fmt.Sprintf("Backup codes error: %v", err), "/protected")
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
	return c.Render("mfa-setup", data)
}

func MFAVerifyPage(c *fiber.Ctx) error {
	return c.Render("mfa-verify", fiber.Map{
		"Title": "MFA Verify",
	})
}

func MFABackupCodesPage(c *fiber.Ctx) error {
	pubHex, _ := c.Locals("user").(string)
	userInfo, exists := objects.Manager.LookupUserByPubHex(pubHex)
	if !exists {
		return renderErrorPage(c, http.StatusNotFound, "User Not Found",
			"User information could not be retrieved.",
			"Please log in again.", "User not found during MFA setup", "/login")
	}
	if !userInfo.MFAEnabled {
		return renderErrorPage(c, http.StatusBadRequest, "MFA Not Enabled",
			"Multi-Factor Authentication is not enabled for your account.",
			"You need to enable MFA first.", "", "/protected")
	}
	// Generate new backup codes
	backupCodes, err := v2.GenerateBackupCodes(10)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Backup Codes Error",
			"Failed to generate new backup codes.",
			"Please try again later.", fmt.Sprintf("Backup codes error: %v", err), "/protected")
	}

	// Get current MFA secret
	secret, _, err := objects.Manager.Vault.GetUserMFA(userInfo.UserID)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "MFA Settings Error",
			"Failed to retrieve MFA settings.",
			"Please try again later.", fmt.Sprintf("MFA get error: %v", err), "/protected")
	}

	// Update with new backup codes
	err = objects.Manager.Vault.SetUserMFA(userInfo.UserID, secret, backupCodes)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Database Error",
			"Failed to save new backup codes.",
			"Please try again later.", fmt.Sprintf("Backup codes save error: %v", err), "/protected")
	}
	return c.Render("mfa-backup-codes", fiber.Map{
		"Title":       "MFA Backup Codes",
		"BackupCodes": backupCodes,
	})
}

func OneTimePage(c *fiber.Ctx) error {
	return c.Render("one-time", fiber.Map{
		"Title": "One Time Password",
	})
}

func PostMFASetup(c *fiber.Ctx) error {
	pubHex, _ := c.Locals("user").(string)
	userInfo, exists := objects.Manager.LookupUserByPubHex(pubHex)
	if !exists {
		return renderErrorPage(c, http.StatusNotFound, "User Not Found",
			"User information could not be retrieved.",
			"Please log in again.", "User not found during MFA setup", "/login")
	}
	var req requests.MFASetupRequest
	if err := c.BodyParser(&req); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Verification Code Required",
			"Please enter the verification code from your authenticator app.",
			"", "", "/mfa/setup")
	}
	if req.Code == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Verification Code Required",
			"Please enter the verification code from your authenticator app.",
			"", "", "/mfa/setup")
	}
	// Get temporary secret from session
	tempSecret, exists := getSessionData(c, "mfa_temp_secret")
	if !exists || tempSecret == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Setup Session Expired",
			"MFA setup session has expired.",
			"Please start the setup process again.", "", "/mfa/setup")
	}

	// Verify the code
	if !v2.VerifyMFACode(req.Code, tempSecret) {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Verification Code",
			"The verification code is incorrect.",
			"Please check your authenticator app and try again.", "", "/mfa/setup")
	}

	// Get backup codes from session
	tempBackupCodesStr, _ := getSessionData(c, "mfa_temp_backup_codes")
	backupCodes := strings.Split(tempBackupCodesStr, ",")

	// Save MFA settings to database
	err := objects.Manager.Vault.SetUserMFA(userInfo.UserID, tempSecret, backupCodes)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Database Error",
			"Failed to save MFA settings.",
			"Please try again later.", fmt.Sprintf("MFA save error: %v", err), "/protected")
	}

	// Enable MFA for the user
	err = objects.Manager.Vault.EnableMFA(userInfo.UserID)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "MFA Enable Error",
			"Failed to enable MFA for your account.",
			"Please try again later.", fmt.Sprintf("MFA enable error: %v", err), "/protected")
	}

	// Clear session data
	clearSessionData(c, "mfa_temp_secret")
	clearSessionData(c, "mfa_temp_backup_codes")
	return c.Render("mfa-enabled", fiber.Map{
		"Title": "MFA Enabled",
	})
}

func PostMFAVerify(c *fiber.Ctx) error {
	var req requests.MFARequest
	if err := c.BodyParser(&req); err != nil {
		return c.Render("mfa-verify", fiber.Map{
			"Error": "Unable to parse request data",
		})
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	code := req.Code
	if username == "" {
		return c.Render("mfa-verify", fiber.Map{
			"Username": username,
			"Error":    "Username and code are required",
		})
	}
	userInfo, hasUser := objects.Manager.LookupUserByUsername(username)
	if !hasUser {
		return c.Render("mfa-verify", fiber.Map{
			"Username": username,
			"Error":    "User not found",
		})
	}
	if !userInfo.MFAEnabled {
		return c.Render("mfa-verify", fiber.Map{
			"Username": username,
			"Error":    "MFA not enabled for this user",
		})
	}
	secret, backupCodes, err := objects.Manager.Vault.GetUserMFA(userInfo.UserID)
	if err != nil {
		return c.Render("mfa-verify", fiber.Map{
			"Username": username,
			"Error":    "Failed to retrieve MFA settings",
		})
	}
	isValid := false
	if len(code) == 6 {
		isValid = v2.VerifyMFACode(code, secret)
	} else if v2.IsBackupCodeFormat(code) {
		formattedCode := v2.FormatBackupCode(code)
		for _, backupCode := range backupCodes {
			if backupCode == formattedCode {
				isValid = true
				objects.Manager.Vault.InvalidateBackupCode(userInfo.UserID, formattedCode)
				break
			}
		}
	}

	if !isValid {
		clientIP := utils.GetClientIP(c)
		objects.Manager.Security.RecordFailedLogin(clientIP)
		return c.Render("mfa-verify", fiber.Map{
			"Username": username,
			"UserInfo": userInfo,
			"Error":    "Invalid MFA code. Please try again.",
		})
	}

	// Based on user's login type, show appropriate login form
	if userInfo.LoginType == "simple" {
		return c.Render("simple-login", fiber.Map{
			"Username": username,
			"UserInfo": userInfo,
		})
	}
	return c.Render("secured-login", fiber.Map{
		"Username": username,
		"UserInfo": userInfo,
	})
}

func PostMFADisable(c *fiber.Ctx) error {
	pubHex, _ := c.Locals("user").(string)
	userInfo, exists := objects.Manager.LookupUserByPubHex(pubHex)
	if !exists {
		return renderErrorPage(c, http.StatusNotFound, "User Not Found",
			"User information could not be retrieved.",
			"Please log in again.", "User not found during MFA disable", "/login")
	}
	var req requests.MFADisableRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Render("mfa-verify", fiber.Map{
			"Error": "Unable to parse request data",
		})
	}
	// Verify current password or MFA code before disabling
	password := req.Password
	if password == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Password Required",
			"Please enter your current password to disable MFA.",
			"", "", "/protected")
	}

	// Verify password
	storedSecret, err := objects.Manager.Vault.GetUserSecret(userInfo.UserID)
	if err != nil || !verifyPassword(password, storedSecret) {
		return renderErrorPage(c, http.StatusUnauthorized, "Invalid Password",
			"The password you entered is incorrect.",
			"Please try again.", "", "/protected")
	}

	// Disable MFA
	err = objects.Manager.Vault.DisableMFA(userInfo.UserID)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "MFA Disable Error",
			"Failed to disable MFA for your account.",
			"Please try again later.", fmt.Sprintf("MFA disable error: %v", err), "/protected")
	}
	return c.Render("mfa-disabled", nil)
}

func PostLogin(c *fiber.Ctx) error {
	var req requests.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Form Data",
			"The form data could not be processed.",
			"Please check your input and try again.",
			fmt.Sprintf("ParseForm error: %v", err), "/login")
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	if username == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Username",
			"Username is required to determine your login method.",
			"Please provide your username (email or phone number).",
			"Missing username field", "/login")
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
			validationErr.Error(), "/login")
	}
	userInfo, hasUser := objects.Manager.LookupUserByUsername(username)
	if !hasUser {
		return renderErrorPage(c, http.StatusNotFound, "User Not Found",
			"No account found with that username.",
			"Please check your username or register for a new account.",
			fmt.Sprintf("Username '%s' not found", username), "/register")
	}
	if userInfo.MFAEnabled {
		return c.Render("mfa-verify", fiber.Map{
			"Username": userInfo.Username,
		})
	}
	if userInfo.LoginType == "simple" {
		return c.Render("simple-login", fiber.Map{
			"Username": userInfo.Username,
			"UserInfo": userInfo,
		})
	}
	return c.Render("secured-login", fiber.Map{
		"Username": userInfo.Username,
		"UserInfo": userInfo,
	})
}

func PostRegister(c *fiber.Ctx) error {
	var req requests.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Form Data",
			"The form data you submitted could not be processed.",
			"Please check that all required fields are filled correctly and try again.",
			fmt.Sprintf("ParseForm error: %v", err), "/register")
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	loginType := strings.ToLower(req.LoginType)
	if loginType != "simple" && loginType != "secured" {
		loginType = "simple" // Default to simple login if invalid type
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
			validationErr.Error(), "/register")
	}
	if username == "" || req.Password == "" || req.ConfirmPassword == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Required Information",
			"Username, password, and password confirmation are required for registration.",
			"Please provide all required fields including password confirmation.",
			"Missing username, password, or confirmPassword fields", "/register")
	}
	if req.Password != req.ConfirmPassword {
		return renderErrorPage(c, http.StatusBadRequest, "Password Mismatch",
			"The passwords you entered do not match.",
			"Please ensure both password fields contain the same value.",
			"Password confirmation mismatch", "/register")
	}
	if err := utils.ValidatePassword(req.Password); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Weak Password",
			"Your password does not meet the security requirements.",
			err.Error(),
			err.Error(), "/register")
	}
	// Check if username (email/phone) already exists
	if _, exists := objects.Manager.LookupUserByUsername(username); exists {
		return renderErrorPage(c, http.StatusConflict, "Username Already Registered",
			"This username is already associated with an existing account.",
			"Please try logging in instead, or use a different email address or phone number.",
			fmt.Sprintf("Username '%s' already exists in database", username), "/login")
	}
	// Only store username for now, keys generated after verification
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Registration System Error",
			"Failed to generate verification token.",
			"Our system encountered an error while processing your registration. Please try again.",
			fmt.Sprintf("Random token generation failed: %v", err), "/register")
	}
	tokenStr := hex.EncodeToString(tokenBytes)
	objects.Manager.SetVerificationToken(username, tokenStr)

	// Store login type preference temporarily
	objects.Manager.Vault.SetUserSecret(username+"_logintype", loginType)

	// Securely hash password and store in vault for later use
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Password Processing Error",
			"Failed to securely process your password.",
			"Our system encountered an error while securing your password. Please try again.",
			fmt.Sprintf("bcrypt hash generation failed: %v", err), "/register")
	}
	objects.Manager.Vault.SetUserSecret(username, string(passwordHash))
	// Store password temporarily for verification step
	objects.Manager.Vault.SetUserSecret(username+"_plain", req.Password)
	if utils.IsEmail(username) {
		utils.SendVerificationEmail(username, tokenStr)
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"message": "Registered. Please check your email for verification.",
		})
	} else if utils.IsPhone(username) {
		utils.SendVerificationSMS(username, tokenStr)
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"message": "Registered. Please check your phone for verification.",
		})
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Registered. Unknown username type, cannot send verification.",
	})
}

func PostForgotPassword(c *fiber.Ctx) error {
	return nil
}

func PostSimpleLogin(c *fiber.Ctx) error {
	var req requests.SimpleLoginRequest
	if err := c.BodyParser(&req); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Form Data",
			"The login form data could not be processed.",
			"Please check your input and try again.",
			fmt.Sprintf("ParseForm error: %v", err), "/login")
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	password := req.Password
	if username == "" || password == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Login Information",
			"Username and password are required for login.",
			"Please provide both your username and password.",
			"Missing username or password fields", "/login")
	}
	clientIP := utils.GetClientIP(c)
	loginIdentifier := fmt.Sprintf("%s:%s", clientIP, username)
	if objects.Manager.Security.IsLoginBlocked(loginIdentifier) {
		return renderErrorPage(c, http.StatusTooManyRequests, "Login Temporarily Blocked",
			"Too many failed login attempts.",
			fmt.Sprintf("Please wait %d minutes before trying again.", int(loginCooldownPeriod.Minutes())),
			fmt.Sprintf("Login blocked for %s from %s", username, clientIP), "/login")
	}
	userInfo, hasUser := objects.Manager.LookupUserByUsername(username)
	if !hasUser {
		objects.Manager.Security.RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Invalid Credentials",
			"The username or password you entered is incorrect.",
			"Please check your credentials and try again, or register for a new account.",
			"Username not found in database", "/login")
	}
	if userInfo.LoginType != "simple" {
		return renderErrorPage(c, http.StatusForbidden, "Secured Login Required",
			"Your account requires secured login with cryptographic key.",
			"Please use the secured login option and provide your cryptographic key.",
			"User account configured for secured login only", "/login")
	}
	storedPassword, err := objects.Manager.Vault.GetUserSecret(userInfo.UserID)
	if err != nil {
		objects.Manager.Security.RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Invalid Credentials",
			"The username or password you entered is incorrect.",
			"Please check your credentials and try again, or register for a new account.",
			"Password hash not found for user", "/login")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password)); err != nil {
		objects.Manager.Security.RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Invalid Credentials",
			"The username or password you entered is incorrect.",
			"Please check your credentials and try again.",
			"Password verification failed", "/login")
	}
	objects.Manager.Security.ClearLoginAttempts(loginIdentifier)
	// Get public key for token creation
	pubKeyX, pubKeyY, err := objects.Manager.GetPublicKeyByUserID(userInfo.UserID)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Account Key Error",
			"Could not retrieve your account's cryptographic keys.",
			"There's an issue with your account setup. Please contact support.",
			fmt.Sprintf("Public key retrieval failed: %v", err), "/login")
	}

	pubHex := pubKeyX + ":" + pubKeyY
	nonce, ts := utils.GetNonceWithTimestamp()

	// Create token claims
	claims := utils.GetClaims(pubHex, nonce, ts)

	// Create PASETO token
	t := token.CreateToken(expDuration, token.AlgEncrypt)
	_ = token.RegisterClaims(t, claims)
	tokenStr, err := token.EncryptToken(t, objects.Manager.Config.PasetoSecret)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Login Token Error",
			"Failed to create authentication token.",
			"There was an internal error during login. Please try again.",
			fmt.Sprintf("PASETO token encryption failed: %v", err), "/login")
	}
	if userInfo, exists := objects.Manager.LookupUserByUsername(username); exists {
		objects.Manager.UserLogoutTracker.ClearUserLogout(userInfo.UserID)
	}
	c.Cookie(utils.GetCookie(objects.Manager.Config.EnableHTTPS, objects.Manager.Config.Environment, "session_token", tokenStr))
	return c.Redirect(AppURI, fiber.StatusSeeOther)
}

func PostSecureLogin(c *fiber.Ctx) error {
	var req requests.SecuredLoginRequest
	if err := c.BodyParser(&req); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Form Data",
			"The login form data could not be processed.",
			"Please check your input and try again.",
			fmt.Sprintf("ParseForm error: %v", err), "/login")
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	password := req.Password
	multipartFile, err := c.FormFile("keyfile")
	if err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Key File",
			"No cryptographic key file was provided.",
			"Please select your .json key file that was downloaded during registration.",
			fmt.Sprintf("FormFile error: %v", err), "/login")
	}
	file, err := multipartFile.Open()
	if err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Key File",
			"No cryptographic key file was provided.",
			"Please select your .json key file that was downloaded during registration.",
			fmt.Sprintf("FormFile error: %v", err), "/login")
	}
	defer file.Close()

	var keyData map[string]string
	if err := json.NewDecoder(file).Decode(&keyData); err != nil {
		log.Printf("Key file decode error: %v", err)
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Key File Format",
			"The key file could not be read or is not in the correct format.",
			"Please ensure you're using the correct .json key file that was downloaded during registration.",
			fmt.Sprintf("JSON decode error: %v", err), "/login")
	}
	pubx, ok1 := keyData["PubKeyX"]
	puby, ok2 := keyData["PubKeyY"]
	encPrivD, ok3 := keyData["EncryptedPrivateKeyD"]
	if !ok1 || !ok2 || !ok3 {
		return renderErrorPage(c, http.StatusBadRequest, "Incomplete Key File",
			"The key file is missing required cryptographic data.",
			"Please ensure you're using the complete, unmodified key file from registration.",
			"Missing PubKeyX, PubKeyY, or EncryptedPrivateKeyD fields", "/login")
	}

	if password == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Password",
			"Password is required to decrypt your private key.",
			"Please enter the password you used during registration.",
			"Password field is empty", "/login")
	}

	// Phase 1: Add rate limiting for secured login
	clientIP := utils.GetClientIP(c)
	pubHex := pubx + ":" + puby
	loginIdentifier := fmt.Sprintf("%s:%s", clientIP, pubHex)

	// Check if login is blocked for this key/IP combination
	if objects.Manager.Security.IsLoginBlocked(loginIdentifier) {
		return renderErrorPage(c, http.StatusTooManyRequests, "Login Temporarily Blocked",
			"Too many failed login attempts.",
			fmt.Sprintf("Please wait %d minutes before trying again.", int(loginCooldownPeriod.Minutes())),
			fmt.Sprintf("Login blocked for key %s from %s", pubHex[:16]+"...", clientIP), "/login")
	}

	info, exists := objects.Manager.LookupUserByPubHex(pubHex)
	if !exists {
		// Phase 1: Record failed login attempt
		objects.Manager.Security.RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Unrecognized Key",
			"This cryptographic key is not associated with any registered user.",
			"Please check that you're using the correct key file, or register for a new account.",
			"Public key not found in user registry", "/register")
	}

	// Verify this matches the username provided
	if info.Username != username {
		return renderErrorPage(c, http.StatusUnauthorized, "Username/Key Mismatch",
			"The cryptographic key does not belong to the specified username.",
			"Please ensure you're using the correct key file for this account.",
			"Username does not match key owner", "/login")
	}

	// Check if user has "simple" login type - they cannot use secured login
	if info.LoginType == "simple" {
		return renderErrorPage(c, http.StatusForbidden, "Simple Login Required",
			"Your account is configured for simple username/password login.",
			"Please use the simple login option with your username and password.",
			"User account configured for simple login only", "/login")
	}

	// Validate public key from credentials table
	storedPubX, storedPubY, err := objects.Manager.GetPublicKeyByUserID(info.UserID)
	if err != nil || storedPubX != pubx || storedPubY != puby {
		// Phase 1: Record failed login attempt
		objects.Manager.Security.RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Key Validation Failed",
			"The cryptographic key does not match our stored credentials.",
			"There may be an issue with your key file or account. Please contact support.",
			"Public key mismatch with stored credentials", "/login")
	}

	passwordHash, err := objects.Manager.Vault.GetUserSecret(info.UserID)
	if err != nil {
		// Phase 1: Record failed login attempt
		objects.Manager.Security.RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Account Verification Failed",
			"Could not verify your account password.",
			"There may be an issue with your account setup. Please contact support.",
			fmt.Sprintf("Password hash retrieval failed: %v", err), "/login")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		// Phase 1: Record failed login attempt
		objects.Manager.Security.RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Incorrect Password",
			"The password you entered is incorrect.",
			"Please check your password and try again. This should be the same password you used during registration.",
			"Password verification failed", "/login")
	}
	privD := utils.DecryptPrivateKeyD(encPrivD, password)
	if _, err := hex.DecodeString(privD); err != nil {
		log.Printf("Decrypted PrivateKeyD is not valid hex: %v", err)
		return renderErrorPage(c, http.StatusUnauthorized, "Key Decryption Failed",
			"Could not decrypt your private key with the provided password.",
			"Please check that you're using the correct password and key file combination.",
			"Private key decryption failed or result is invalid hex", "/login")
	}

	nonce, ts := utils.GetNonceWithTimestamp()
	proof := v2.GenerateProof(privD, nonce, ts)
	if err := v2.VerifyProofWithReplay(objects.Manager, &proof); err != nil {
		// Phase 1: Record failed login attempt
		objects.Manager.Security.RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Cryptographic Proof Failed",
			"The cryptographic proof verification failed.",
			"There was an issue with the authentication process. Please try again.",
			fmt.Sprintf("Proof verification failed: %v", err), "/login")
	}

	// Phase 1: Clear failed login attempts on successful authentication
	objects.Manager.Security.ClearLoginAttempts(loginIdentifier)
	claims := utils.GetClaims(pubHex, nonce, ts)
	t := token.CreateToken(expDuration, token.AlgEncrypt)
	_ = token.RegisterClaims(t, claims)
	tokenStr, err := token.EncryptToken(t, objects.Manager.Config.PasetoSecret)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Token Generation Failed",
			"Failed to generate authentication token.",
			"There was an internal error during login. Please try again.",
			fmt.Sprintf("PASETO token encryption failed: %v", err), "/login")
	}
	c.Cookie(utils.GetCookie(objects.Manager.Config.EnableHTTPS, objects.Manager.Config.Environment, "session_token", tokenStr))
	return c.Redirect(AppURI, fiber.StatusSeeOther)
}

func PostLogout(c *fiber.Ctx) error {
	tokenStr := ""
	cookie := c.Cookies("session_token")
	if cookie != "" {
		tokenStr = cookie
	} else if c.Get("Authorization") != "" {
		tokenStr = strings.ReplaceAll(c.Get("Authorization"), "Bearer ", "")
	}
	if tokenStr == "" {
		return renderErrorPage(c, http.StatusBadRequest, "No Authentication Token",
			"No authentication token found for logout.",
			"You don't appear to be logged in. Please log in first if you want to access protected areas.",
			"No session_token cookie or Authorization header found", "/login")
	}
	decTok, err := token.DecryptToken(tokenStr, objects.Manager.Config.PasetoSecret)
	if err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Authentication Token",
			"The authentication token could not be processed for logout.",
			"Your session may have been corrupted. Please try logging in again.",
			fmt.Sprintf("Token decryption failed during logout: %v", err), "/login")
	}
	exp, _ := decTok.Claims["exp"].(int64)
	if exp == 0 {
		// fallback for float64
		if expf, ok := decTok.Claims["exp"].(float64); ok {
			exp = int64(expf)
		}
	}
	objects.Manager.CleanupExpiredTokens()
	objects.Manager.AddTokenToDenylist(tokenStr, exp)

	// CRITICAL SECURITY: Also logout from proof-based authentication
	// Extract user ID from token to invalidate proof-based access
	if sub, ok := decTok.Claims["sub"].(string); ok {
		if userInfo, exists := objects.Manager.LookupUserByPubHex(sub); exists {
			// Initialize logout tracker if needed
			// Set user as logged out for proof-based github.com/oarkflow/auth
			objects.Manager.UserLogoutTracker.SetUserLogout(userInfo.UserID)
		}
	}

	c.Cookie(utils.GetCookie(objects.Manager.Config.EnableHTTPS, objects.Manager.Config.Environment, "session_token", tokenStr, -1))

	// Add cache control headers to prevent browser caching
	c.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Set("Pragma", "no-cache")
	c.Set("Expires", "0")
	return c.Redirect(LogoutURI+"?success=1", http.StatusSeeOther)
}

func renderErrorPage(c *fiber.Ctx, statusCode int, title, message, description, technical, retryURL string) error {
	errorID := fmt.Sprintf("ERR-%d-%d", time.Now().Unix(), statusCode)
	data := models.ErrorPageData{
		Title:       title,
		StatusCode:  statusCode,
		Message:     message,
		Description: description,
		Technical:   technical,
		RetryURL:    retryURL,
		ErrorID:     errorID,
	}
	return c.Render("error", data)
}
