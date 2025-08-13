package handlers

import (
	"github.com/gofiber/fiber/v2"
)

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

func Setup(prefix string, router fiber.Router) {
	route := router.Group(prefix)
	route.Get(HealthURI, HealthCheck)
	route.Get(LandingURI, LandingPage)
	route.Get(VerifyURI, VerifyPage)
	route.Get(LoginURI, LoginPage)
	route.Post(LoginURI, PostLogin)
	route.Get(RegisterURI, RegisterPage)
	route.Post(RegisterURI, PostRegister)
	route.Post(SimpleLoginURI, PostSimpleLogin)
	route.Post(SecuredLoginURI, PostSecureLogin)
	route.Get(ForgotPasswordURI, ForgotPasswordPage)
	route.Post(ForgotPasswordURI, PostForgotPassword)
	route.Get(OneTimeURI, OneTimePage)
	route.Get(MFAVerifyURI, MFAVerifyPage)
	route.Post(MFAVerifyURI, PostMFAVerify)
}

func ProtectedRoutes(route fiber.Router) {
	route.Get(AppURI, DashboardPage)
	route.Get(LogoutURI, LogoutPage)
	route.Post(LogoutURI, PostLogout)
	route.Get(UserInfoURI, UserInfoPage)
	route.Get(MFASetupURI, MFASetupPage)
	route.Post(MFASetupURI, PostMFASetup)
	route.Post(MFADisableURI, PostMFADisable)
	route.Get(MFABackupCodesURI, MFABackupCodesPage)
}
