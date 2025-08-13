package requests

type LoginRequest struct {
	Username string `json:"username"`
}

type SimpleLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type SecuredLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
