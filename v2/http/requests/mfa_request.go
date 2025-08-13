package requests

type MFARequest struct {
	Username string `json:"username"`
	Code     string `json:"code"`
}
