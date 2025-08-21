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
	"github.com/oarkflow/hash"
	"github.com/oarkflow/paseto/token"
	"github.com/oarkflow/xid/wuid"

	"github.com/oarkflow/auth/pkg/http/requests"
	"github.com/oarkflow/auth/pkg/http/responses"
	"github.com/oarkflow/auth/pkg/libs"
	"github.com/oarkflow/auth/pkg/models"
	"github.com/oarkflow/auth/pkg/objects"
	"github.com/oarkflow/auth/pkg/utils"
)

const (
	loginCooldownPeriod = 15 * time.Minute
)

func DashboardPage(c *fiber.Ctx) error {
	pubHex, _ := c.Locals("user").(string)
	info, _ := c.Locals("userInfo").(models.UserInfo)
	return responses.Render(c, utils.AppTemplate, fiber.Map{
		"PubHex":   pubHex,
		"DBUserID": info.UserID,
		"Username": info.Username,
	})
}

func HealthCheck(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
	})
}

func LandingPage(c *fiber.Ctx) error {
	return responses.Render(c, utils.LandingTemplate, fiber.Map{
		"Title": "Welcome to the Auth Service",
	})
}

func UserInfoPage(c *fiber.Ctx) error {
	pubHex, _ := c.Locals("user").(string)
	info, _ := c.Locals("userInfo").(models.UserInfo)
	// Get public key details
	pubKeyX, pubKeyY, err := objects.Manager.GetPublicKeyByUserID(info.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to retrieve user keys",
		})
	}

	// Get MFA status
	mfaEnabled, _ := objects.Manager.Vault().IsUserMFAEnabled(info.UserID)
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
	return responses.Render(c, utils.LogoutTemplate, fiber.Map{
		"Title": "Logout page",
	})
}

func VerifyPage(c *fiber.Ctx) error {
	var req requests.VerifyRequest
	if err := c.QueryParser(&req); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Form Data",
			"The verification form data could not be processed.",
			"Please check your input and try again.",
			fmt.Sprintf("ParseForm error: %v", err), utils.RegisterURI)
	}
	username := req.Username
	token := req.Token
	if username == "" || token == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Verification Link",
			"The verification link is missing required parameters.",
			"Please check that you clicked the complete link from your email or SMS, or try registering again.",
			"Missing username or token in verification URL", utils.RegisterURI)
	}
	// Use verification token table
	ok, err := objects.Manager.Vault().VerifyToken(username, token)
	if err != nil || !ok {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Verification",
			"This verification link is either invalid or has already been used.",
			"The link may have expired or been used already. Please try registering again to get a new verification link.",
			"Verification token does not match or does not exist", utils.RegisterURI)
	}

	// Retrieve pending registration data
	passwordHash, loginType, err := objects.Manager.Vault().GetPendingRegistration(username)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Account Setup Error",
			"Failed to complete account setup due to missing registration information.",
			"There was an issue finalizing your account. Please try registering again.",
			"Pending registration not found during verification", utils.RegisterURI)
	}

	// Generate key pair after verification
	pubx, puby, privd := libs.GenerateKeyPair()
	pubHex := libs.PadHex(pubx) + ":" + libs.PadHex(puby)
	info := models.UserInfo{
		UserID:    wuid.New().Int64(),
		Username:  username,
		LoginType: loginType,
		PubHex:    pubHex,
	}
	objects.Manager.Vault().SetUserInfo(pubHex, info)
	objects.Manager.Vault().SetUserPublicKey(info.UserID, libs.PadHex(pubx), libs.PadHex(puby))
	objects.Manager.RegisterUserKey(pubHex, []byte(pubx), []byte(puby))
	objects.Manager.Vault().SetUserSecret(info.UserID, passwordHash)

	encPrivD := utils.EncryptPrivateKeyD(privd, passwordHash)
	keyData := map[string]string{
		"PubKeyX":              libs.PadHex(pubx),
		"PubKeyY":              libs.PadHex(puby),
		"EncryptedPrivateKeyD": encPrivD,
	}
	jsonData, _ := json.Marshal(keyData)
	return responses.Render(c, utils.DownloadKeyTemplate, fiber.Map{
		"KeyJson": template.JS(jsonData),
	})
}

func LoginPage(c *fiber.Ctx) error {
	return responses.Render(c, utils.LoginTemplate, fiber.Map{
		"Title": "Login",
	})
}

func RegisterPage(c *fiber.Ctx) error {
	return responses.Render(c, utils.RegisterTemplate, fiber.Map{
		"Title": "Register",
	})
}

func OneTimePage(c *fiber.Ctx) error {
	return responses.Render(c, utils.OneTimeTemplate, fiber.Map{
		"Title": "One Time Password",
	})
}

func PostLogin(c *fiber.Ctx) error {
	var req requests.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Form Data",
			"The form data could not be processed.",
			"Please check your input and try again.",
			fmt.Sprintf("ParseForm error: %v", err), utils.LoginURI)
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	if username == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Username",
			"Username is required to determine your login method.",
			"Please provide your username (email or phone number).",
			"Missing username field", utils.LoginURI)
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
			validationErr.Error(), utils.LoginURI)
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
	if userInfo.LoginType == "simple" {
		return responses.Render(c, utils.SimpleLoginTemplate, fiber.Map{
			"Username": userInfo.Username,
			"UserInfo": userInfo,
		})
	}
	return responses.Render(c, utils.SecuredLoginTemplate, fiber.Map{
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
			fmt.Sprintf("ParseForm error: %v", err), utils.RegisterURI)
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	loginType := strings.ToLower(req.LoginType)
	if loginType != "simple" && loginType != "secured" {
		loginType = "simple"
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
			validationErr.Error(), utils.RegisterURI)
	}
	if username == "" || req.Password == "" || req.ConfirmPassword == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Required Information",
			"Username, password, and password confirmation are required for registration.",
			"Please provide all required fields including password confirmation.",
			"Missing username, password, or confirmPassword fields", utils.RegisterURI)
	}
	if req.Password != req.ConfirmPassword {
		return renderErrorPage(c, http.StatusBadRequest, "Password Mismatch",
			"The passwords you entered do not match.",
			"Please ensure both password fields contain the same value.",
			"Password confirmation mismatch", utils.RegisterURI)
	}
	if err := utils.ValidatePassword(req.Password); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Weak Password",
			"Your password does not meet the security requirements.",
			err.Error(),
			err.Error(), utils.RegisterURI)
	}
	// Check if username (email/phone) already exists
	if _, exists := objects.Manager.LookupUserByUsername(username); exists {
		return renderErrorPage(c, http.StatusConflict, "Username Already Registered",
			"This username is already associated with an existing account.",
			"Please try logging in instead, or use a different email address or phone number.",
			fmt.Sprintf("Username '%s' already exists in database", username), utils.LoginURI)
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Registration System Error",
			"Failed to generate verification token.",
			"Our system encountered an error while processing your registration. Please try again.",
			fmt.Sprintf("Random token generation failed: %v", err), utils.RegisterURI)
	}
	tokenStr := hex.EncodeToString(tokenBytes)
	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	objects.Manager.Vault().SetVerificationToken(username, tokenStr, expiresAt)

	passwordHash, err := hash.Make(req.Password, objects.Config.GetString("auth.password_algo"))
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Password Processing Error",
			"Failed to securely process your password.",
			"Our system encountered an error while securing your password. Please try again.",
			fmt.Sprintf("bcrypt hash generation failed: %v", err), utils.RegisterURI)
	}
	// Store pending registration (username, password hash, login type)
	if err := objects.Manager.Vault().CreatePendingRegistration(username, string(passwordHash), loginType); err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Registration Storage Error",
			"Failed to store registration data.",
			"Our system encountered an error while saving your registration. Please try again.",
			fmt.Sprintf("Pending registration storage failed: %v", err), utils.RegisterURI)
	}
	manager, ok := objects.Manager.(*libs.Manager)
	emailSender := utils.SendVerificationEmail
	smsSender := utils.SendVerificationSMS
	if ok {
		if manager.SendNotification.SendVerificationEmail != nil {
			emailSender = manager.SendNotification.SendVerificationEmail
		}
		if manager.SendNotification.SendVerificationSMS != nil {
			smsSender = manager.SendNotification.SendVerificationSMS
		}
	}
	if utils.IsPhone(username) {

		smsSender(c, username, tokenStr)
		return responses.Render(c, utils.VerificationSentTemplate, fiber.Map{
			"Title":   "Verification Sent",
			"Message": "Registered. Please check your phone for verification.",
			"Contact": username,
		})
	}
	emailSender(c, username, tokenStr)
	return responses.Render(c, utils.VerificationSentTemplate, fiber.Map{
		"Title":   "Verification Sent",
		"Message": "Registered. Please check your email for verification.",
		"Contact": username,
	})
}

func PostSimpleLogin(c *fiber.Ctx) error {
	sessionTimeout := objects.Config.GetDuration("auth.session_timeout", "24h")
	var req requests.SimpleLoginRequest
	if err := c.BodyParser(&req); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Form Data",
			"The login form data could not be processed.",
			"Please check your input and try again.",
			fmt.Sprintf("ParseForm error: %v", err), utils.LoginURI)
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
	password := req.Password
	if username == "" || password == "" {
		return renderErrorPage(c, http.StatusBadRequest, "Missing Login Information",
			"Username and password are required for login.",
			"Please provide both your username and password.",
			"Missing username or password fields", utils.LoginURI)
	}
	clientIP := utils.GetClientIP(c)
	loginIdentifier := fmt.Sprintf("%s:%s", clientIP, username)
	if objects.Manager.Security().IsLoginBlocked(loginIdentifier) {
		return renderErrorPage(c, http.StatusTooManyRequests, "Login Temporarily Blocked",
			"Too many failed login attempts.",
			fmt.Sprintf("Please wait %d minutes before trying again.", int(loginCooldownPeriod.Minutes())),
			fmt.Sprintf("Login blocked for %s from %s", username, clientIP), utils.LoginURI)
	}
	userInfo, hasUser := objects.Manager.LookupUserByUsername(username)
	if !hasUser {
		objects.Manager.Security().RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Invalid Credentials",
			"The username or password you entered is incorrect.",
			"Please check your credentials and try again, or register for a new account.",
			"Username not found in database", utils.LoginURI)
	}
	if userInfo.LoginType != "simple" {
		return renderErrorPage(c, http.StatusForbidden, "Secured Login Required",
			"Your account requires secured login with cryptographic key.",
			"Please use the secured login option and provide your cryptographic key.",
			"User account configured for secured login only", utils.LoginURI)
	}
	storedPassword, err := objects.Manager.Vault().GetUserSecret(userInfo.UserID)
	if err != nil {
		objects.Manager.Security().RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Invalid Credentials",
			"The username or password you entered is incorrect.",
			"Please check your credentials and try again, or register for a new account.",
			"Password hash not found for user", utils.LoginURI)
	}

	ok, err := verifyPassword(password, storedPassword)
	if err != nil || !ok {
		objects.Manager.Security().RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Invalid Credentials",
			"The username or password you entered is incorrect.",
			"Please check your credentials and try again.",
			"Password verification failed", utils.LoginURI)
	}
	objects.Manager.Security().ClearLoginAttempts(loginIdentifier)
	// Get public key for token creation
	pubKeyX, pubKeyY, err := objects.Manager.GetPublicKeyByUserID(userInfo.UserID)
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Account Key Error",
			"Could not retrieve your account's cryptographic keys.",
			"There's an issue with your account setup. Please contact support.",
			fmt.Sprintf("Public key retrieval failed: %v", err), utils.LoginURI)
	}

	pubHex := pubKeyX + ":" + pubKeyY
	nonce, ts := utils.GetNonceWithTimestamp()

	// Create token claims
	claims := utils.GetClaims(pubHex, nonce, ts)
	t := token.CreateToken(sessionTimeout, token.AlgEncrypt)
	_ = token.RegisterClaims(t, claims)

	secret := objects.Config.GetString("auth.secret")
	tokenStr, err := token.EncryptToken(t, []byte(secret))
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Login Token Error",
			"Failed to create authentication token.",
			"There was an internal error during login. Please try again.",
			fmt.Sprintf("PASETO token encryption failed: %v", err), utils.LoginURI)
	}
	if userInfo, exists := objects.Manager.LookupUserByUsername(username); exists {
		objects.Manager.LogoutTracker().ClearUserLogout(userInfo.UserID)
	}
	enableHTTPS := objects.Config.GetBool("app.https")
	appEnv := objects.Config.GetString("app.env")
	sessionName := objects.Config.GetString("auth.session_name")
	c.Cookie(utils.GetCookie(enableHTTPS, appEnv, sessionName, tokenStr, int(sessionTimeout.Seconds())))
	manager, ok := objects.Manager.(*libs.Manager)
	uri := utils.AppURI
	if ok && manager.LoginSuccessURL != "" {
		uri = manager.LoginSuccessURL
	}
	// Check for last_visited_uri cookie
	lastVisited := c.Cookies("last_visited_uri")
	if lastVisited != "" {
		// Clear the cookie
		c.Cookie(&fiber.Cookie{
			Name:     "last_visited_uri",
			Value:    "",
			Path:     "/",
			HTTPOnly: true,
			Expires:  time.Unix(0, 0),
		})
		return c.Redirect(lastVisited, fiber.StatusSeeOther)
	}
	return c.Redirect(uri, fiber.StatusSeeOther)
}

func PostSecureLogin(c *fiber.Ctx) error {
	sessionTimeout := objects.Config.GetDuration("auth.session_timeout", "24h")
	var req requests.SecuredLoginRequest
	if err := c.BodyParser(&req); err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Form Data",
			"The login form data could not be processed.",
			"Please check your input and try again.",
			fmt.Sprintf("ParseForm error: %v", err), utils.LoginURI)
	}
	username := utils.SanitizeInput(strings.TrimSpace(req.Username))
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
		log.Printf("Key file decode error: %v", err)
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
	clientIP := utils.GetClientIP(c)
	pubHex := pubx + ":" + puby
	loginIdentifier := fmt.Sprintf("%s:%s", clientIP, pubHex)

	// Check if login is blocked for this key/IP combination
	if objects.Manager.Security().IsLoginBlocked(loginIdentifier) {
		return renderErrorPage(c, http.StatusTooManyRequests, "Login Temporarily Blocked",
			"Too many failed login attempts.",
			fmt.Sprintf("Please wait %d minutes before trying again.", int(loginCooldownPeriod.Minutes())),
			fmt.Sprintf("Login blocked for key %s from %s", pubHex[:16]+"...", clientIP), utils.LoginURI)
	}

	info, exists := objects.Manager.LookupUserByPubHex(pubHex)
	if !exists {
		// Phase 1: Record failed login attempt
		objects.Manager.Security().RecordFailedLogin(loginIdentifier)
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

	// Check if user has "simple" login type - they cannot use secured login
	if info.LoginType == "simple" {
		return renderErrorPage(c, http.StatusForbidden, "Simple Login Required",
			"Your account is configured for simple username/password login.",
			"Please use the simple login option with your username and password.",
			"User account configured for simple login only", utils.LoginURI)
	}

	// Validate public key from credentials table
	storedPubX, storedPubY, err := objects.Manager.GetPublicKeyByUserID(info.UserID)
	if err != nil || storedPubX != pubx || storedPubY != puby {
		// Phase 1: Record failed login attempt
		objects.Manager.Security().RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Key Validation Failed",
			"The cryptographic key does not match our stored credentials.",
			"There may be an issue with your key file or account. Please contact support.",
			"Public key mismatch with stored credentials", utils.LoginURI)
	}

	passwordHash, err := objects.Manager.Vault().GetUserSecret(info.UserID)
	if err != nil {
		// Phase 1: Record failed login attempt
		objects.Manager.Security().RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Account Verification Failed",
			"Could not verify your account password.",
			"There may be an issue with your account setup. Please contact support.",
			fmt.Sprintf("Password hash retrieval failed: %v", err), utils.LoginURI)
	}

	ok, err := verifyPassword(password, passwordHash)
	if err != nil || !ok {
		objects.Manager.Security().RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Incorrect Password",
			"The password you entered is incorrect.",
			"Please check your password and try again. This should be the same password you used during registration.",
			"Password verification failed", utils.LoginURI)
	}
	privD := utils.DecryptPrivateKeyD(encPrivD, passwordHash)
	if _, err := hex.DecodeString(privD); err != nil {
		log.Printf("Decrypted PrivateKeyD is not valid hex: %v", err)
		return renderErrorPage(c, http.StatusUnauthorized, "Key Decryption Failed",
			"Could not decrypt your private key with the provided password.",
			"Please check that you're using the correct password and key file combination.",
			"Private key decryption failed or result is invalid hex", utils.LoginURI)
	}

	nonce, ts := utils.GetNonceWithTimestamp()
	proof := libs.GenerateProof(privD, nonce, ts)
	if err := libs.VerifyProofWithReplay(objects.Manager, &proof); err != nil {
		// Phase 1: Record failed login attempt
		objects.Manager.Security().RecordFailedLogin(loginIdentifier)
		return renderErrorPage(c, http.StatusUnauthorized, "Cryptographic Proof Failed",
			"The cryptographic proof verification failed.",
			"There was an issue with the authentication process. Please try again.",
			fmt.Sprintf("Proof verification failed: %v", err), utils.LoginURI)
	}

	// Phase 1: Clear failed login attempts on successful authentication
	objects.Manager.Security().ClearLoginAttempts(loginIdentifier)
	claims := utils.GetClaims(pubHex, nonce, ts)
	t := token.CreateToken(sessionTimeout, token.AlgEncrypt)
	_ = token.RegisterClaims(t, claims)
	secret := objects.Config.GetString("auth.secret")
	tokenStr, err := token.EncryptToken(t, []byte(secret))
	if err != nil {
		return renderErrorPage(c, http.StatusInternalServerError, "Login Token Error",
			"Failed to create authentication token.",
			"There was an internal error during login. Please try again.",
			fmt.Sprintf("PASETO token encryption failed: %v", err), utils.LoginURI)
	}

	enableHTTPS := objects.Config.GetBool("app.https")
	appEnv := objects.Config.GetString("app.env")
	sessionName := objects.Config.GetString("auth.session_name")
	c.Cookie(utils.GetCookie(enableHTTPS, appEnv, sessionName, tokenStr))
	manager, ok := objects.Manager.(*libs.Manager)
	uri := utils.AppURI
	if ok && manager.LoginSuccessURL != "" {
		uri = manager.LoginSuccessURL
	}
	// Check for last_visited_uri cookie
	lastVisited := c.Cookies("last_visited_uri")
	if lastVisited != "" {
		// Clear the cookie
		c.Cookie(&fiber.Cookie{
			Name:     "last_visited_uri",
			Value:    "",
			Path:     "/",
			HTTPOnly: true,
			Expires:  time.Unix(0, 0),
		})
		return c.Redirect(lastVisited, fiber.StatusSeeOther)
	}
	return c.Redirect(uri, fiber.StatusSeeOther)
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
			"No session_token cookie or Authorization header found", utils.LoginURI)
	}
	secret := objects.Config.GetString("auth.secret")
	decTok, err := token.DecryptToken(tokenStr, []byte(secret))
	if err != nil {
		return renderErrorPage(c, http.StatusBadRequest, "Invalid Authentication Token",
			"The authentication token could not be processed for logout.",
			"Your session may have been corrupted. Please try logging in again.",
			fmt.Sprintf("Token decryption failed during logout: %v", err), utils.LoginURI)
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
			objects.Manager.LogoutTracker().SetUserLogout(userInfo.UserID)
		}
	}

	enableHTTPS := objects.Config.GetBool("app.https")
	appEnv := objects.Config.GetString("app.env")
	sessionName := objects.Config.GetString("auth.session_name")
	c.Cookie(utils.GetCookie(enableHTTPS, appEnv, sessionName, tokenStr, -1))

	// Add cache control headers to prevent browser caching
	c.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Set("Pragma", "no-cache")
	c.Set("Expires", "0")
	return c.Redirect(utils.LogoutURI+"?success=1", http.StatusSeeOther)
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
	return responses.Render(c, utils.ErrorTemplate, data)
}
