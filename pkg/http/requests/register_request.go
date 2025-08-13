package requests

type RegisterRequest struct {
	Username        string `json:"username" form:"username"`
	Password        string `json:"password" form:"password"`
	ConfirmPassword string `json:"confirmPassword" form:"confirmPassword"`
	LoginType       string `json:"login_type" form:"login_type"` // "simple" or "secured"
}
