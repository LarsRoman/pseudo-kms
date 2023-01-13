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
	if strings.Contains(string(h), "256") {
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
	if strings.Contains(string(h), "256") {
		return crypto.SHA256
	}
	if strings.Contains(string(h), "512") {
		return crypto.SHA512
	}
	if strings.Contains(string(h), "384") {
		return crypto.SHA384
	}
	return crypto.Hash(0)
}

func (h Hashes) CreateHashFromDigest(digest []byte) []byte {
	if h.CryptoString() == crypto.Hash(0) {
		return digest
	}
	if h.CryptoString() == crypto.SHA256 {
		var puffer [32]byte = sha256.Sum256(digest)
		return puffer[:]
	}
	if h.CryptoString() == crypto.SHA384 {
		var puffer [48]byte = sha512.Sum384(digest)
		return puffer[:]
	}
	if h.CryptoString() == crypto.SHA512 {
		var puffer [64]byte = sha512.Sum512(digest)
		return puffer[:]
	}
	return digest
}

func FromString(hash string) Hashes {
	if strings.Contains(hash, "1") {
		return SHA1
	}
	if strings.Contains(hash, "256") {
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
