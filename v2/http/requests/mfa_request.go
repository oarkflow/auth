package requests

type MFARequest struct {
	Username string `json:"username" form:"username"`
	Code     string `json:"code" form:"code"`
}

type MFASetupRequest struct {
	Code string `json:"code" form:"code"`
}

type MFADisableRequest struct {
	Password string `json:"password" form:"password"`
}
