package routes

import (
	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/auth/pkg/http/handlers"
	"github.com/oarkflow/auth/pkg/utils"
)

func Setup(prefix string, router fiber.Router) {
	route := router.Group(prefix)
	route.Get(utils.HealthURI, handlers.HealthCheck)
	route.Get(utils.LandingURI, handlers.LandingPage)
	route.Get(utils.VerifyURI, handlers.VerifyPage)
	route.Get(utils.LoginURI, handlers.LoginPage)
	route.Post(utils.LoginURI, handlers.PostLogin)
	route.Get(utils.RegisterURI, handlers.RegisterPage)
	route.Post(utils.RegisterURI, handlers.PostRegister)
	route.Post(utils.SimpleLoginURI, handlers.PostSimpleLogin)
	route.Post(utils.SecuredLoginURI, handlers.PostSecureLogin)
	route.Get(utils.ForgotPasswordURI, handlers.ForgotPasswordPage)
	route.Post(utils.ForgotPasswordURI, handlers.PostForgotPassword)
	route.Get(utils.OneTimeURI, handlers.OneTimePage)
	route.Get(utils.MFAVerifyURI, handlers.MFAVerifyPage)
	route.Post(utils.MFAVerifyURI, handlers.PostMFAVerify)
}

func ProtectedRoutes(route fiber.Router) {
	route.Get(utils.AppURI, handlers.DashboardPage)
	route.Get(utils.LogoutURI, handlers.LogoutPage)
	route.Post(utils.LogoutURI, handlers.PostLogout)
	route.Get(utils.UserInfoURI, handlers.UserInfoPage)
	route.Get(utils.MFASetupURI, handlers.MFASetupPage)
	route.Post(utils.MFASetupURI, handlers.PostMFASetup)
	route.Post(utils.MFADisableURI, handlers.PostMFADisable)
	route.Get(utils.MFABackupCodesURI, handlers.MFABackupCodesPage)
}
