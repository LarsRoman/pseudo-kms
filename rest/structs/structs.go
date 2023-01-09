package structs

import "lars-krieger.de/pseudo-kms/crypt/helper"

type GinUser struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

type GinNewUser struct {
	GinUser  GinUser
	Username string `json:"newusername"`
	Token    string `json:"newtoken"`
}

type GinCreateKey struct {
	GinUser           GinUser
	AsymmetricKeyType helper.KeyTypes `json:"keytype"`
	KeyOps            string          `json:"keyops"`
	KeyName           string          `json:"keyname"`
	KeyVersion        int             `json:"keyversion"`
}

type GinKey struct {
	GinUser GinUser
	KeyName string `json:"keyname"`
	Message string `json:"msg"`
	Hash    string `json:"hash"`
}
