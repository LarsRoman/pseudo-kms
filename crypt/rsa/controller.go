package rsa

import (
	"crypto/rsa"
	"lars-krieger.de/pseudo-kms/crypt/helper"
)

type RSA struct {
	PrivateKey    rsa.PrivateKey
	PublicKey     rsa.PublicKey
	KeySize       int
	AsymmetricOpt helper.AsymmetricOpt
}

func (r RSA) Create() ([]byte, []byte) {
	if r.KeySize > 0 {
		privateKey, publicKey := GeneratePrivateKey(r.KeySize, r.AsymmetricOpt.WriteToFile)
		r.PrivateKey = *privateKey
		r.PublicKey = *publicKey
	} else {
		privateKey, publicKey := GenerateDefaultPrivateKey(r.AsymmetricOpt.WriteToFile)
		r.PrivateKey = *privateKey
		r.PublicKey = *publicKey
	}
	return PrivateKeyToMem(&r.PrivateKey), PublicKeyToMem(&r.PublicKey)
}

func (r RSA) GetAlg() helper.KeyTypes {
	return helper.RSA
}

func (r RSA) GetInfo() helper.AsymmetricOpt {
	return helper.AsymmetricOpt{}
}

func (r RSA) Sign(msg string) string {
	return helper.ToHex(SignPKCS1v15(r.PrivateKey, helper.UNDEFINED, helper.FromHex(msg)))
}

func (r RSA) SignWithHash(msg, hash string) string {
	return helper.ToHex(SignPKCS1v15(r.PrivateKey, helper.FromString(hash), helper.FromHex(msg)))
}

func (r RSA) Encrypt(msg string) string {
	return helper.ToHex(EncryptPKCS1v15(r.PublicKey, helper.FromHex(msg)))
}

func (r RSA) Decrypt(msg string) string {
	return helper.ToHex(DecryptPKCS1v15(r.PrivateKey, helper.FromHex(msg)))
}
