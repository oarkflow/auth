package requests

type VerifyRequest struct {
	Username string `json:"username" query:"username"`
	Token    string `json:"token" query:"token"`
}
