package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/labstack/gommon/log"
	"os"
	"time"
)

var defaultRsaKeySize int = 2048

func GenerateDefaultPrivateKey(writeFile bool) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, defaultRsaKeySize)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	publicKey := &privateKey.PublicKey
	if writeFile {
		privateKeyToFile(privateKey)
		publicKeyToFile(publicKey)
	}
	return privateKey, publicKey
}

func GeneratePrivateKey(leng int, writeFile bool) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, leng)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	publicKey := &privateKey.PublicKey
	if writeFile {
		privateKeyToFile(privateKey)
		publicKeyToFile(publicKey)
	}
	return privateKey, publicKey
}

func privateKeyToFile(privateKey *rsa.PrivateKey) {
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	fileName := fmt.Sprintf("/data/pseudo-kms/private-%d.pem", time.Now().UnixNano())
	privatePem, err := os.Create(fileName)
	if err != nil {
		log.Errorf("Error when creating %s: %s \n", fileName, err.Error())
		return
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		log.Errorf("Error when encode %s: %s \n", fileName, err.Error())
		return
	}

	if privatePem.Close() != nil {
		log.Errorf("Error when closing %s: %s \n", fileName, err.Error())
		return
	}
}

func PrivateKeyToMem(privateKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
}

func MemToPrivateKey(privateKeyBytes []byte) *rsa.PrivateKey {
	block, rest := pem.Decode(privateKeyBytes)
	if len(rest) > 0 {
		log.Infof("Decoding private Key left a rest: %v", rest)
	}
	if privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		log.Errorf("Unable to Parse Private Key: %s", err.Error())
		return nil
	} else {
		return privateKey
	}
}

func PublicKeyToMem(privateKey *rsa.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(privateKey),
	})
}

func MemToPublicKey(publicKeyBytes []byte) *rsa.PublicKey {
	block, rest := pem.Decode(publicKeyBytes)
	if len(rest) > 0 {
		log.Infof("Decoding Public Key left a rest: %v", rest)
	}
	if publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
		log.Errorf("Unable to Parse Public Key: %s", err.Error())
		return nil
	} else {
		return publicKey
	}
}

func publicKeyToFile(publicKey *rsa.PublicKey) {
	publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create("/data/pseudo-kms/public.pem")
	if err != nil {
		log.Errorf("error when create public.pem: %s \n", err)
		defer publicPem.Close()
		return
	}
	if err := pem.Encode(publicPem, publicKeyBlock); err != nil {
		log.Errorf("error when encode public pem: %s \n", err)
		defer publicPem.Close()
		return
	}
}
