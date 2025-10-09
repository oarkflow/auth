package utils

import "strings"

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
	LoginSelectionURI     = "/login-selection"
	SupportEmail          = "support@example.com"
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

func GetURIs(prefix string) map[string]string {
	return map[string]string{
		"Landing":            strings.ReplaceAll(prefix+LandingURI, "//", "/"),
		"App":                strings.ReplaceAll(prefix+AppURI, "//", "/"),
		"Login":              strings.ReplaceAll(prefix+LoginURI, "//", "/"),
		"Register":           strings.ReplaceAll(prefix+RegisterURI, "//", "/"),
		"ResendVerification": strings.ReplaceAll(prefix+ResendVerificationURI, "//", "/"),
		"Verify":             strings.ReplaceAll(prefix+VerifyURI, "//", "/"),
		"ForgotPassword":     strings.ReplaceAll(prefix+ForgotPasswordURI, "//", "/"),
		"OneTime":            strings.ReplaceAll(prefix+OneTimeURI, "//", "/"),
		"SimpleLogin":        strings.ReplaceAll(prefix+SimpleLoginURI, "//", "/"),
		"SecuredLogin":       strings.ReplaceAll(prefix+SecuredLoginURI, "//", "/"),
		"MFAVerify":          strings.ReplaceAll(prefix+MFAVerifyURI, "//", "/"),
		"Logout":             strings.ReplaceAll(prefix+LogoutURI, "//", "/"),
		"UserInfo":           strings.ReplaceAll(prefix+UserInfoURI, "//", "/"),
		"MFASetup":           strings.ReplaceAll(prefix+MFASetupURI, "//", "/"),
		"MFADisable":         strings.ReplaceAll(prefix+MFADisableURI, "//", "/"),
		"MFABackupCodes":     strings.ReplaceAll(prefix+MFABackupCodesURI, "//", "/"),
		"Health":             strings.ReplaceAll(prefix+HealthURI, "//", "/"),
		"ResetPassword":      strings.ReplaceAll(prefix+ResetPasswordURI, "//", "/"),
		"LoginSelection":     strings.ReplaceAll(prefix+LoginSelectionURI, "//", "/"),
		"SupportEmail":       SupportEmail,
	}
}

var DefaultSessionName = "session_name"
