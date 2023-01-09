package database

import (
	"encoding/hex"
	"github.com/labstack/gommon/log"
	"lars-krieger.de/pseudo-kms/crypt"
	"lars-krieger.de/pseudo-kms/crypt/helper"
	"lars-krieger.de/pseudo-kms/database/models"
)

func GetOrCreateKey(ops crypt.AsymmetricOps, username, token string) models.Keys {
	var opt helper.AsymmetricOpt = ops.GetInfo()
	var keystore models.Keystore = GetOrCreateKeystore(username, token)
	var key models.Keys
	DB.First(&key, models.Keys{
		KeyName:    opt.Name,
		KeyVersion: opt.Version,
		Keystore:   keystore,
	})
	if key.KeyVersion == 0 {
		privateKey, publicKey := ops.Create()
		CreateKey(opt.Name, string(ops.GetAlg()), "", privateKey, publicKey, 1, keystore)
		DB.First(&key, models.Keys{
			KeyName:    opt.Name,
			KeyVersion: 1,
			Keystore:   keystore,
		})
	}
	return key
}

func CreateKey(keyName, keyAlg, keyUse string, privateKey, publicKey []byte, keyVersion int, keystore models.Keystore) {
	DB.Create(models.Keys{
		KeyName:    keyName,
		KeyVersion: keyVersion,
		KeyAlg:     keyAlg,
		KeyUse:     keyUse,
		PrivateKey: toHex(privateKey),
		PublicKey:  toHex(publicKey),
		Keystore:   keystore,
	})
}

func RotateKey(key models.Keys, privateKey, publicKey []byte) {
	key.PrivateKey = toHex(privateKey)
	key.PublicKey = toHex(publicKey)
	key.KeyVersion = key.KeyVersion + 1
	DB.Create(key)
}

func GetCurrentKey(username, token, keyName string) models.Keys {
	var keystore models.Keystore = GetOrCreateKeystore(username, token)
	//TODO I need to read the GORM documentation because the following is shitty
	var keyArr []models.Keys
	DB.Find(&keyArr, models.Keys{
		KeyName:  keyName,
		Keystore: keystore,
	})
	//TODO Should be done by DB
	var key models.Keys = keyArr[0]
	for _, k := range keyArr {
		if k.KeyVersion > key.KeyVersion {
			key = k
		}
	}
	return key
}

func toHex(bArr []byte) string {
	return hex.EncodeToString(bArr)
}

func fromHex(hexString string) []byte {
	if bArr, err := hex.DecodeString(hexString); err != nil {
		log.Errorf("Decoding of Hex to ByteArray was not possible: %s", err.Error())
	} else {
		return bArr
	}
	return []byte{}
}
