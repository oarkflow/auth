package requests

type ResendVerificationRequest struct {
	Username string `json:"username" form:"username"`
}
