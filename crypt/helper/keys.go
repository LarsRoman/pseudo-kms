package helper

import "strings"

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
	ECDSA         ECCKeyTypes = "ECDSA"
	ECDSA_SHA_256 ECCKeyTypes = "ECDSA_SHA_256"
	ECDSA_SHA_384 ECCKeyTypes = "ECDSA_SHA_384"
	ECDSA_SHA_512 ECCKeyTypes = "ECDSA_SHA_512"
)

func (k ECCKeyTypes) ToString() string {
	return string(k)
}

func (k ECCKeyTypes) ToHash() Hashes {
	if strings.Contains(k.ToString(), "265") {
		return SHA256
	}
	if strings.Contains(k.ToString(), "384") {
		return SHA384
	}
	if strings.Contains(k.ToString(), "5125") {
		return SHA512
	}
	return UNDEFINED
}
