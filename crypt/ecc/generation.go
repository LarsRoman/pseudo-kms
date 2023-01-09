package ecc

import (
	"crypto/elliptic"
	"github.com/labstack/gommon/log"
	"gitlab.com/elktree/ecc"
)

var defaultCurve elliptic.Curve = elliptic.P256()

func GenerateDefaultPrivateKey() (*ecc.PrivateKey, *ecc.PublicKey) {
	return GeneratePrivateKey(defaultCurve)
}

func GeneratePrivateKey(curve elliptic.Curve) (*ecc.PrivateKey, *ecc.PublicKey) {
	publicKey, privateKey, err := ecc.GenerateKeys(curve)
	if err != nil {
		log.Errorf("Creating of ECC Key Pair was not possible: %s", err.Error())
		return nil, nil
	}
	return privateKey, publicKey
}

func PrivateKeyToMem(privateKey *ecc.PrivateKey) []byte {
	if keyPEM, err := privateKey.PEM(""); err != nil {
		log.Errorf("Creating of ECC Private Key PEM was not possible: %s", err.Error())
	} else {
		return keyPEM
	}
	return nil
}

func PublicKeyToMem(publicKey *ecc.PublicKey) []byte {
	if keyPEM, err := publicKey.PEM(); err != nil {
		log.Errorf("Creating of ECC PublicKey Key PEM was not possible: %s", err.Error())
	} else {
		return keyPEM
	}
	return nil
}
