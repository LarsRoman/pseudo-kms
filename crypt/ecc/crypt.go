package ecc

import (
	"github.com/labstack/gommon/log"
	"gitlab.com/elktree/ecc"
)

func Encrypt(publicKey *ecc.PublicKey, digest []byte) []byte {
	if encrypted, err := publicKey.Encrypt(digest); err != nil {
		log.Errorf("ECC Encryption failed: %s", err.Error())
	} else {
		return encrypted
	}
	return nil
}

func Decrypt(privateKey *ecc.PrivateKey, digest []byte) []byte {
	if decrypted, err := privateKey.Decrypt(digest); err != nil {
		log.Errorf("ECC Decryption failed: %s", err.Error())
	} else {
		return decrypted
	}
	return nil
}

func sign(privateKey *ecc.PrivateKey, digest []byte) []byte {
	if sig, err := privateKey.SignMessage(digest); err != nil {
		log.Errorf("ECC Signing failed: %s", err.Error())
	} else {
		return sig
	}
	return nil
}

func Verify(publicKey *ecc.PublicKey, digest, signature []byte) bool {
	if verified, err := publicKey.VerifyMessage(digest, signature); err != nil {
		log.Errorf("ECC signature verification failed: %s", err.Error())
	} else {
		return verified
	}
	return false
}
