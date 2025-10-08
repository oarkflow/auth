package requests

type LoginRequest struct {
	Username string `json:"username"`
}

type SimpleLoginRequest struct {
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
	Redirect string `json:"redirect" form:"redirect"`
}

type SecuredLoginRequest struct {
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
	Redirect string `json:"redirect" form:"redirect"`
}
