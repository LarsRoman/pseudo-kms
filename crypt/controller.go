package crypt

import (
	"lars-krieger.de/pseudo-kms/crypt/helper"
	"lars-krieger.de/pseudo-kms/database/models"
)

type AsymmetricKeyOps interface {
	Create() ([]byte, []byte)
	GetAlg() string
	GetInfo() helper.AsymmetricOpt
	Sign(msg string) string
	SignWithHash(msg string, hash string) string
	Encrypt(msg string) string
	Decrypt(msg string) string
	Bind(models.Keys)
	GetPublicKeyPemHex() string
}
