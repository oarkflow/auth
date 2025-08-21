package routes

import (
	"slices"

	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/auth/pkg/http/handlers"
	"github.com/oarkflow/auth/pkg/objects"
	"github.com/oarkflow/auth/pkg/utils"
)

func Setup(prefix string, router fiber.Router) {
	route := router.Group(prefix)
	DisabledRoutes(route, "Get", utils.HealthURI, handlers.HealthCheck)
	DisabledRoutes(route, "Get", utils.LandingURI, handlers.LandingPage)
	DisabledRoutes(route, "Get", utils.VerifyURI, handlers.VerifyPage)
	DisabledRoutes(route, "Get", utils.ResetPasswordURI, handlers.PasswordResetPage)
	DisabledRoutes(route, "Post", utils.ResetPasswordURI, handlers.PostResetPassword)
	DisabledRoutes(route, "Get", utils.LoginURI, handlers.LoginPage)
	DisabledRoutes(route, "Post", utils.LoginURI, handlers.PostLogin)
	DisabledRoutes(route, "Get", utils.RegisterURI, handlers.RegisterPage)
	DisabledRoutes(route, "Post", utils.RegisterURI, handlers.PostRegister)
	DisabledRoutes(route, "Post", utils.SimpleLoginURI, handlers.PostSimpleLogin)
	DisabledRoutes(route, "Post", utils.SecuredLoginURI, handlers.PostSecureLogin)
	DisabledRoutes(route, "Get", utils.ForgotPasswordURI, handlers.ForgotPasswordPage)
	DisabledRoutes(route, "Post", utils.ForgotPasswordURI, handlers.PostForgotPassword)
	DisabledRoutes(route, "Get", utils.OneTimeURI, handlers.OneTimePage)
	DisabledRoutes(route, "Get", utils.MFAVerifyURI, handlers.MFAVerifyPage)
	DisabledRoutes(route, "Post", utils.MFAVerifyURI, handlers.PostMFAVerify)
}

func ProtectedRoutes(route fiber.Router) {
	DisabledRoutes(route, "Get", utils.AppURI, handlers.DashboardPage)
	DisabledRoutes(route, "Post", utils.LogoutURI, handlers.PostLogout)
	DisabledRoutes(route, "Get", utils.UserInfoURI, handlers.UserInfoPage)
	DisabledRoutes(route, "Get", utils.MFASetupURI, handlers.MFASetupPage)
	DisabledRoutes(route, "Post", utils.MFASetupURI, handlers.PostMFASetup)
	DisabledRoutes(route, "Post", utils.MFADisableURI, handlers.PostMFADisable)
	DisabledRoutes(route, "Get", utils.MFABackupCodesURI, handlers.MFABackupCodesPage)
}

func DisabledRoutes(route fiber.Router, method, uri string, handlers ...fiber.Handler) {
	disabledRoutes := objects.Manager.DisabledRoutes()
	if len(disabledRoutes) == 0 {
		route.Add(method, uri, handlers...)
	} else if !slices.Contains(disabledRoutes, uri) {
		route.Add(method, uri, handlers...)
	}
}
