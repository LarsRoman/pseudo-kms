package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/labstack/gommon/log"
	"lars-krieger.de/pseudo-kms/crypt/helper"
)

func EncryptOEP(publicKey rsa.PublicKey, hash helper.Hashes, message []byte) []byte {
	if encryptedBytes, err := rsa.EncryptOAEP(
		hash.HashString(),
		rand.Reader,
		&publicKey,
		message,
		nil); err != nil {
		log.Errorf("RSA Encryption failed")
	} else {
		return encryptedBytes
	}
	return nil
}

func EncryptPKCS1v15(publicKey rsa.PublicKey, message []byte) []byte {
	if encryptedBytes, err := rsa.EncryptPKCS1v15(
		rand.Reader,
		&publicKey,
		message); err != nil {
		log.Errorf("RSA Encryption failed")
	} else {
		return encryptedBytes
	}
	return nil
}

func decryptOEP(privateKey rsa.PrivateKey, hash helper.Hashes, message []byte) []byte {
	if plainText, err := rsa.DecryptOAEP(
		hash.HashString(),
		rand.Reader,
		&privateKey,
		message,
		nil); err != nil {
		log.Errorf("RSA Decryption failed")
	} else {
		return plainText
	}
	return nil
}

func DecryptPKCS1v15(privateKey rsa.PrivateKey, message []byte) []byte {
	if plainText, err := rsa.DecryptPKCS1v15(
		rand.Reader,
		&privateKey,
		message); err != nil {
		log.Errorf("RSA Decryption failed")
	} else {
		return plainText
	}
	return nil
}

func signPSS(privateKey rsa.PrivateKey, hash helper.Hashes, digest []byte) []byte {
	if signature, err := rsa.SignPSS(
		rand.Reader,
		&privateKey,
		hash.CryptoString(),
		digest,
		nil); err != nil {
		log.Errorf("Signing PSS failed: %s", err.Error())
	} else {
		return signature
	}
	return nil
}

func SignPKCS1v15(privateKey rsa.PrivateKey, hash helper.Hashes, digest []byte) []byte {
	if signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		&privateKey,
		hash.CryptoString(),
		hash.CreateHashFromDigest(digest)); err != nil {
		log.Errorf("Signing PKCS1v15 %s failed: %s",
			fmt.Sprintf("with hash %s", hash), err.Error())
		if hash.CryptoString() == crypto.Hash(0) {
			log.Infof("Trying to sign with SHA 256")
			return SignPKCS1v15(privateKey, helper.FromString("256"), digest)
		}
	} else {
		return signature
	}
	return nil
}
