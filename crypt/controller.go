package crypt

import "lars-krieger.de/pseudo-kms/crypt/helper"

type AsymmetricOps interface {
	Create() ([]byte, []byte)
	GetAlg() helper.KeyTypes
	GetInfo() helper.AsymmetricOpt
	Sign(msg string) string
	SignWithHash(msg string, hash string) string
	Encrypt(msg string) string
	Decrypt(msg string) string
}
