package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	v2 "github.com/oarkflow/auth/v2"
	"github.com/oarkflow/auth/v2/http/requests"
	"github.com/oarkflow/auth/v2/objects"
	"github.com/oarkflow/auth/v2/utils"
	"github.com/oarkflow/paseto/token"
	"golang.org/x/crypto/bcrypt"
)

const (
	expDuration = 15 * time.Minute
)

func LandingPage(c *fiber.Ctx) error {
	return c.Render("index", fiber.Map{
		"Title": "Welcome to the Auth Service",
	})
}

func VerifyPage(c *fiber.Ctx) error {
	return c.Render("verify", fiber.Map{
		"Title": "Welcome to the Auth Service",
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
	return c.Render("mfa-setup", fiber.Map{
		"Title": "MFA Setup",
	})
}

func MFAVerifyPage(c *fiber.Ctx) error {
	return c.Render("mfa-verify", fiber.Map{
		"Title": "MFA Verify",
	})
}

func MFABackupCodesPage(c *fiber.Ctx) error {
	return c.Render("mfa-backup-codes", fiber.Map{
		"Title": "MFA Backup Codes",
	})
}

func OneTimePage(c *fiber.Ctx) error {
	return c.Render("one-time", fiber.Map{
		"Title": "One Time Password",
	})
}

func PostMFASetup(c *fiber.Ctx) error {
	return nil
}

func PostMFAVerify(c *fiber.Ctx) error {
	var req requests.MFARequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	code := req.Code
	if username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username is required"})
	}
	userInfo, hasUser := objects.Manager.LookupUserByUsername(username)
	if !hasUser {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}
	mfaEnabled, err := objects.Manager.Vault.IsUserMFAEnabled(username)
	if err != nil || !mfaEnabled {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "MFA is not enabled for this user"})
	}
	secret, backupCodes, err := objects.Manager.Vault.GetUserMFA(userInfo.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve MFA data"})
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
	return nil
}

func PostLogin(c *fiber.Ctx) error {
	var req requests.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	if username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username is required"})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": validationErr.Error()})
	}
	userInfo, hasUser := objects.Manager.LookupUserByUsername(username)
	if !hasUser {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	if username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username is required"})
	}
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": validationErr.Error()})
	}
	if username == "" || req.Password == "" || req.ConfirmPassword == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username, password, and confirm password are required"})
	}
	if req.Password != req.ConfirmPassword {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Passwords do not match"})
	}
	if err := utils.ValidatePassword(req.Password); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	// Check if username (email/phone) already exists
	if _, exists := objects.Manager.LookupUserByUsername(username); exists {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Username already exists"})
	}
	// Only store username for now, keys generated after verification
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate verification token"})
	}
	token := hex.EncodeToString(tokenBytes)
	objects.Manager.SetVerificationToken(username, token)

	// Store login type preference temporarily
	objects.Manager.Vault.SetUserSecret(username+"_logintype", loginType)

	// Securely hash password and store in vault for later use
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}
	objects.Manager.Vault.SetUserSecret(username, string(passwordHash))
	// Store password temporarily for verification step
	objects.Manager.Vault.SetUserSecret(username+"_plain", req.Password)
	if utils.IsEmail(username) {
		utils.SendVerificationEmail(username, token)
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"message": "Registered. Please check your email for verification.",
		})
	} else if utils.IsPhone(username) {
		utils.SendVerificationSMS(username, token)
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	password := req.Password
	if username == "" || password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username and password are required"})
	}
	clientIP := utils.GetClientIP(c)
	loginIdentifier := fmt.Sprintf("%s:%s", clientIP, username)
	if objects.Manager.Security.IsLoginBlocked(loginIdentifier) {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "Too many login attempts. Please try again later."})
	}
	userInfo, hasUser := objects.Manager.LookupUserByUsername(username)
	if !hasUser {
		objects.Manager.Security.RecordFailedLogin(loginIdentifier)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}
	if userInfo.LoginType != "simple" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "User does not support simple login"})
	}
	storedPassword, err := objects.Manager.Vault.GetUserSecret(username + "_plain")
	if err != nil {
		objects.Manager.Security.RecordFailedLogin(loginIdentifier)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve user password"})
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password)); err != nil {
		objects.Manager.Security.RecordFailedLogin(loginIdentifier)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
	}
	objects.Manager.Security.ClearLoginAttempts(loginIdentifier)
	// Get public key for token creation
	pubKeyX, pubKeyY, err := objects.Manager.GetPublicKeyByUserID(userInfo.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve user public key"})
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
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create authentication token"})
	}
	c.Cookie(utils.GetCookie(objects.Manager.Config.EnableHTTPS, objects.Manager.Config.Environment, tokenStr))
	return nil
}

func PostSecureLogin(c *fiber.Ctx) error {
	return nil
}

func PostLogout(c *fiber.Ctx) error {
	return nil
}
