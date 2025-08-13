package utils

var (
	LandingURI        = "/"
	HealthURI         = "/health"
	AppURI            = "/app"
	LoginURI          = "/login"
	RegisterURI       = "/register"
	VerifyURI         = "/verify"
	ForgotPasswordURI = "/forgot-password"
	OneTimeURI        = "/one-time"
	SimpleLoginURI    = "/login/simple"
	SecuredLoginURI   = "/login/secured"
	MFAVerifyURI      = "/mfa/verify"
	LogoutURI         = "/logout"
	UserInfoURI       = "/api/userinfo"
	MFASetupURI       = "/mfa/setup"
	MFADisableURI     = "/mfa/disable"
	MFABackupCodesURI = "/mfa/backup-codes"
)

func GetURIs() map[string]string {
	return map[string]string{
		"Landing":        LandingURI,
		"App":            AppURI,
		"Login":          LoginURI,
		"Register":       RegisterURI,
		"Verify":         VerifyURI,
		"ForgotPassword": ForgotPasswordURI,
		"OneTime":        OneTimeURI,
		"SimpleLogin":    SimpleLoginURI,
		"SecuredLogin":   SecuredLoginURI,
		"MFAVerify":      MFAVerifyURI,
		"Logout":         LogoutURI,
		"UserInfo":       UserInfoURI,
		"MFASetup":       MFASetupURI,
		"MFADisable":     MFADisableURI,
		"MFABackupCodes": MFABackupCodesURI,
	}
}
