package requests

type RegisterRequest struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirmPassword"`
	LoginType       string `json:"login_type"` // "simple" or "secured"
}
