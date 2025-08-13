package handlers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/auth/v2/http/middlewares"
)

func Setup(prefix string, router fiber.Router) {
	route := router.Group(prefix)
	route.Get("/", LandingPage)
	route.Get("/verify", VerifyPage)
	route.Get("/login", LoginPage)
	route.Post("/login", PostLogin)
	route.Get("/register", RegisterPage)
	route.Post("/register", PostRegister)
	route.Post("/login/simple", PostSimpleLogin)
	route.Post("/login/secured", PostSecureLogin)
	route.Get("/forgot-password", ForgotPasswordPage)
	route.Post("/forgot-password", PostForgotPassword)
	route.Get("/one-time", OneTimePage)
	route.Get("/mfa/verify", MFAVerifyPage)
	route.Post("/mfa/verify", PostMFAVerify)

	protectedRoute := route.Group("/", middlewares.Verify)
	protectedRoute.Get("/app", DashboardPage)
	protectedRoute.Get("/logout", LogoutPage)
	protectedRoute.Post("/logout", PostLogout)
	protectedRoute.Get("/api/userinfo", UserInfoPage)
	protectedRoute.Get("/mfa/setup", MFASetupPage)
	protectedRoute.Post("/mfa/setup", PostMFASetup)
	protectedRoute.Post("/mfa/disable", PostMFADisable)
	protectedRoute.Get("/mfa/backup-codes", MFABackupCodesPage)
}
