package helper

import (
	"crypto/elliptic"
	"strings"
)

type KeyTypes string

const (
	RSA     KeyTypes = "RSA"
	ECC     KeyTypes = "EC"
	UNKNOWN KeyTypes = ""
)

func (k KeyTypes) ToString() string {
	return string(k)
}

type RSAKeyTypes string

const (
	RSASSA_PSS_SHA_256        RSAKeyTypes = "RSASSA_PSS_SHA_256"
	RSASSA_PSS_SHA_384        RSAKeyTypes = "RSASSA_PSS_SHA_384"
	RSASSA_PSS_SHA_512        RSAKeyTypes = "RSASSA_PSS_SHA_512"
	RSASSA_PKCS1_V1_5         RSAKeyTypes = "RSASSA_PKCS1_V1_5"
	RSASSA_PKCS1_V1_5_SHA_256 RSAKeyTypes = "RSASSA_PKCS1_V1_5_SHA_256"
	RSASSA_PKCS1_V1_5_SHA_384 RSAKeyTypes = "RSASSA_PKCS1_V1_5_SHA_384"
	RSASSA_PKCS1_V1_5_SHA_512 RSAKeyTypes = "RSASSA_PKCS1_V1_5_SHA_512"
)

func (k RSAKeyTypes) ToString() string {
	return string(k)
}

func (k RSAKeyTypes) ToHash() Hashes {
	if strings.Contains(k.ToString(), "265") {
		return SHA256
	}
	if strings.Contains(k.ToString(), "384") {
		return SHA384
	}
	if strings.Contains(k.ToString(), "512") {
		return SHA512
	}
	return UNDEFINED
}

type ECCKeyTypes string

const (
	ECDSA_P256         ECCKeyTypes = "ECDSA_P256"
	ECDSA_P256_SHA_256 ECCKeyTypes = "ECDSA_P256_SHA_256"
	ECDSA_P384_SHA_384 ECCKeyTypes = "ECDSA_P384_SHA_384"
	ECDSA_P512_SHA_512 ECCKeyTypes = "ECDSA_P512_SHA_512"
)

func (k ECCKeyTypes) ToString() string {
	return string(k)
}

func (k ECCKeyTypes) ToHash() Hashes {
	if strings.Contains(k.ToString(), "_265") {
		return SHA256
	}
	if strings.Contains(k.ToString(), "_384") {
		return SHA384
	}
	if strings.Contains(k.ToString(), "_512") {
		return SHA512
	}
	return UNDEFINED
}

func (k ECCKeyTypes) ToCurve() elliptic.Curve {
	if strings.Contains(k.ToString(), "384") {
		return elliptic.P384()
	}
	if strings.Contains(k.ToString(), "512") {
		return elliptic.P521()
	}
	return elliptic.P256()
}
