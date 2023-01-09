package ecc

import (
	"crypto/elliptic"
	"gitlab.com/elktree/ecc"
	"lars-krieger.de/pseudo-kms/crypt/helper"
)

type ECC struct {
	PrivateKey    ecc.PrivateKey
	PublicKey     ecc.PublicKey
	Curve         elliptic.Curve
	AsymmetricOpt helper.AsymmetricOpt
}

func (e ECC) Create() ([]byte, []byte) {
	privateKey, publicKey := GeneratePrivateKey(e.Curve)
	e.PrivateKey = *privateKey
	e.PublicKey = *publicKey
	return PrivateKeyToMem(&e.PrivateKey), PublicKeyToMem(&e.PublicKey)
}

func (e ECC) GetAlg() helper.KeyTypes {
	return helper.ECC
}

func (e ECC) GetInfo() helper.AsymmetricOpt {
	return helper.AsymmetricOpt{}
}

func (e ECC) Sign(msg string) string {
	return helper.ToHex(sign(&e.PrivateKey, helper.FromHex(msg)))
}

func (e ECC) SignWithHash(msg, hash string) string {
	var hasher = helper.FromString(hash).HashString()
	hasher.Write(helper.FromHex(msg))
	return helper.ToHex(sign(&e.PrivateKey, []byte((msg))))
}

func (e ECC) Encrypt(msg string) string {
	return helper.ToHex(Encrypt(&e.PublicKey, helper.FromHex(msg)))
}

func (e ECC) Decrypt(msg string) string {
	return helper.ToHex(Decrypt(&e.PrivateKey, helper.FromHex(msg)))
}
