package helper

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"strings"
)

type Hashes string

const (
	SHA256    Hashes = "sha256"
	SHA384    Hashes = "SHA384"
	SHA512    Hashes = "SHA512"
	SHA1      Hashes = "SHA1"
	UNDEFINED Hashes = ""
)

func (h Hashes) HashString() hash.Hash {
	if strings.Contains(string(h), "1") {
		return sha1.New()
	}
	if strings.Contains(string(h), "265") {
		return sha256.New()
	}
	if strings.Contains(string(h), "512") {
		return sha512.New()
	}
	if strings.Contains(string(h), "384") {
		return sha512.New384()
	}
	return nil
}

func (h Hashes) CryptoString() crypto.Hash {
	if strings.Contains(string(h), "1") {
		return crypto.SHA1
	}
	if strings.Contains(string(h), "265") {
		return crypto.SHA256
	}
	if strings.Contains(string(h), "512") {
		return crypto.SHA512
	}
	if strings.Contains(string(h), "384") {
		return crypto.SHA384
	}
	return 0
}

func FromString(hash string) Hashes {
	if strings.Contains(hash, "1") {
		return SHA1
	}
	if strings.Contains(hash, "265") {
		return SHA256
	}
	if strings.Contains(hash, "512") {
		return SHA512
	}
	if strings.Contains(hash, "384") {
		return SHA384
	}
	return UNDEFINED
}
