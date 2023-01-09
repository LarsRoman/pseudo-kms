package helper

import (
	"encoding/hex"
	"github.com/labstack/gommon/log"
)

func ToHex(bArr []byte) string {
	return hex.EncodeToString(bArr)
}

func FromHex(hexString string) []byte {
	if bArr, err := hex.DecodeString(hexString); err != nil {
		log.Errorf("Decoding of Hex to ByteArray was not possible: %s", err.Error())
	} else {
		return bArr
	}
	return []byte{}
}
