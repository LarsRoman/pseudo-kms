package structs

type GinUser struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

type GinNewUser struct {
	GinUser  GinUser
	Username string `json:"newusername"`
	Token    string `json:"newtoken"`
}

type GinDeleteUser struct {
	GinUser        GinUser
	DeleteUsername string `json:"deleteusername"`
}

type GinCreateKey struct {
	GinUser           GinUser
	AsymmetricKeyType string `json:"keytype"`
	KeyCurve          string `json:"keycurve"`
	KeyOps            string `json:"keyops"`
	KeySize           int    `json:"keysize"`
	KeyName           string `json:"keyname"`
	KeyVersion        int    `json:"keyversion"`
}

type GinKey struct {
	GinUser GinUser
	KeyName string `json:"keyname"`
	Message string `json:"msg"`
	Hash    string `json:"hash"`
}

type GinDeleteKey struct {
	GinUser    GinUser
	KeyName    string `json:"keyname"`
	KeyVersion int    `json:"keyversion"`
}
