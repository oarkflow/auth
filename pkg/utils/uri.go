package utils

var (
	LandingURI            = "/"
	HealthURI             = "/health"
	AppURI                = "/app"
	LoginURI              = "/login"
	RegisterURI           = "/register"
	ResendVerificationURI = "/resend-verification"
	VerifyURI             = "/verify"
	ForgotPasswordURI     = "/forgot-password"
	ResetPasswordURI      = "/reset-password"
	OneTimeURI            = "/one-time"
	SimpleLoginURI        = "/login/simple"
	SecuredLoginURI       = "/login/secured"
	MFAVerifyURI          = "/mfa/verify"
	LogoutURI             = "/logout"
	UserInfoURI           = "/api/userinfo"
	MFASetupURI           = "/mfa/setup"
	MFADisableURI         = "/mfa/disable"
	MFABackupCodesURI     = "/mfa/backup-codes"
)

var (
	LandingTemplate              = "auth/index"
	DownloadKeyTemplate          = "auth/download-key-file"
	HealthTemplate               = "auth/health"
	AppTemplate                  = "auth/protected"
	LoginTemplate                = "auth/login"
	RegisterTemplate             = "auth/register"
	VerifyTemplate               = "auth/verify"
	ForgotPasswordTemplate       = "auth/forgot-password"
	OneTimeTemplate              = "auth/one-time"
	SimpleLoginTemplate          = "auth/simple-login"
	SecuredLoginTemplate         = "auth/secured-login"
	MFAVerifyTemplate            = "auth/mfa-verify"
	LogoutTemplate               = "auth/logout"
	UserInfoTemplate             = "auth/userinfo"
	MFAEnabledTemplate           = "auth/mfa-enabled"
	MFADisabledTemplate          = "auth/mfa-disabled"
	MFASetupTemplate             = "auth/mfa-setup"
	PasswordResetTemplate        = "auth/password-reset"
	ErrorTemplate                = "auth/error"
	MFABackupCodesTemplate       = "auth/mfa-backup-codes"
	VerificationSentTemplate     = "auth/verification-sent"
	PendingRegistrationTemplate  = "auth/pending-registration"
	PasswordResetSuccessTemplate = "auth/password-reset-success"
)

func GetURIs() map[string]string {
	return map[string]string{
		"Landing":            LandingURI,
		"App":                AppURI,
		"Login":              LoginURI,
		"Register":           RegisterURI,
		"ResendVerification": ResendVerificationURI,
		"Verify":             VerifyURI,
		"ForgotPassword":     ForgotPasswordURI,
		"OneTime":            OneTimeURI,
		"SimpleLogin":        SimpleLoginURI,
		"SecuredLogin":       SecuredLoginURI,
		"MFAVerify":          MFAVerifyURI,
		"Logout":             LogoutURI,
		"UserInfo":           UserInfoURI,
		"MFASetup":           MFASetupURI,
		"MFADisable":         MFADisableURI,
		"MFABackupCodes":     MFABackupCodesURI,
	}
}

var DefaultSessionName = "session_name"
