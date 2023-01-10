package ecc

import (
	"crypto/elliptic"
	"gitlab.com/elktree/ecc"
	"lars-krieger.de/pseudo-kms/crypt/helper"
	"lars-krieger.de/pseudo-kms/database/models"
	"strings"
)

type ECC struct {
	PrivateKey    ecc.PrivateKey
	PublicKey     ecc.PublicKey
	Curve         elliptic.Curve
	AsymmetricOpt helper.AsymmetricOpt
}

func (e *ECC) Create() ([]byte, []byte) {
	privateKey, publicKey := GeneratePrivateKey(e.Curve)
	e.PrivateKey = *privateKey
	e.PublicKey = *publicKey
	return PrivateKeyToMem(&e.PrivateKey), PublicKeyToMem(&e.PublicKey)
}

func (e ECC) GetAlg() string {
	return e.AsymmetricOpt.KeyTypes
}

func (e ECC) GetInfo() helper.AsymmetricOpt {
	return e.AsymmetricOpt
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

func (e *ECC) Bind(key models.Keys) {
	privateKey := ecc.PrivateKey{}
	if key.PrivateKey != "" {
		privateKey = *MemToPrivateKey(helper.FromHex(key.PrivateKey))
	}
	publicKey := ecc.PublicKey{}
	if key.PublicKey != "" {
		publicKey = *MemToPublicKey(helper.FromHex(key.PublicKey))
	}
	*e = *&ECC{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Curve:      getCurve(key.KeyCurve),
		AsymmetricOpt: helper.AsymmetricOpt{
			Name:        key.KeyName,
			Version:     key.KeyVersion,
			WriteToFile: false,
			Hash:        helper.ECCKeyTypes.ToHash(helper.ECCKeyTypes(key.KeyAlg)),
			KeyTypes:    string(helper.ECCKeyTypes(key.KeyAlg)),
		},
	}
}

func getCurve(curve string) elliptic.Curve {
	if strings.Contains(curve, "224") {
		return elliptic.P224()
	}
	if strings.Contains(curve, "256") {
		return elliptic.P256()
	}
	if strings.Contains(curve, "384") {
		return elliptic.P384()
	}
	if strings.Contains(curve, "521") {
		return elliptic.P521()
	}
	return nil
}
