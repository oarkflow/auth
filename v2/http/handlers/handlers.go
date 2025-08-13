package handlers

import "github.com/gofiber/fiber/v2"

func Setup(prefix string, router fiber.Router) {
	route := router.Group(prefix)
	route.Get("/", LandingPage)
	route.Get("/verify", VerifyPage)
	route.Get("/login", LoginPage)
	route.Post("/login", PostLogin)
	route.Get("/register", RegisterPage)
	route.Post("/register", PostRegister)
	route.Get("/forgot-password", ForgotPasswordPage)
	route.Post("/forgot-password", PostForgotPassword)
	route.Post("/logout", PostLogout)
	route.Get("/one-time", OneTimePage)

	mfaRoute := route.Group("/mfa")
	mfaRoute.Get("/setup", MFASetupPage)
	mfaRoute.Post("/setup", PostMFASetup)
	mfaRoute.Get("/verify", MFAVerifyPage)
	mfaRoute.Post("/verify", PostMFAVerify)
	mfaRoute.Post("/disable", PostMFADisable)
	mfaRoute.Get("/backup-codes", MFABackupCodesPage)
}
