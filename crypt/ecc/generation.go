package ecc

import (
	"crypto/elliptic"
	"encoding/pem"
	"github.com/labstack/gommon/log"
	"gitlab.com/elktree/ecc"
)

var defaultCurve elliptic.Curve = elliptic.P256()

func GenerateDefaultPrivateKey() (*ecc.PrivateKey, *ecc.PublicKey) {
	return GeneratePrivateKey(defaultCurve)
}

func GeneratePrivateKey(curve elliptic.Curve) (*ecc.PrivateKey, *ecc.PublicKey) {
	if curve == nil {
		log.Infof("No Curve was provided. Using %v", defaultCurve.Params())
		return GenerateDefaultPrivateKey()
	}
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

func MemToPrivateKey(privateKey []byte) *ecc.PrivateKey {
	block, rest := pem.Decode(privateKey)
	if len(rest) > 0 {
		log.Infof("Decoding private Key left a rest: %v", rest)
	}
	if pK, err := ecc.UnmarshalPrivateKey(block.Bytes); err != nil {
		log.Errorf("Creating the Private key from DB failed: %s ", err.Error())
	} else {
		return pK
	}
	return nil
}

func MemToPublicKey(publicKey []byte) *ecc.PublicKey {
	if pK, err := ecc.DecodePEMPublicKey(publicKey); err != nil {
		log.Errorf("Creating the Public key from DB failed: %s ", err.Error())
	} else {
		return pK
	}
	return nil
}
