package database

import (
	"lars-krieger.de/pseudo-kms/crypt"
	"lars-krieger.de/pseudo-kms/crypt/helper"
	"lars-krieger.de/pseudo-kms/database/models"
)

func GetOrCreateKey(ops crypt.AsymmetricKeyOps, username, token string) models.Keys {
	var opt helper.AsymmetricOpt = ops.GetInfo()
	var keystore models.Keystore = GetOrCreateKeystore(username, token)
	var key models.Keys
	DB.Where(&models.Keys{
		KeyName:    opt.Name,
		KeyVersion: opt.Version,
		Keystore:   keystore,
	}).First(&key)
	if key.KeyVersion == 0 {
		privateKey, publicKey := ops.Create()
		CreateKey(opt.Name, string(ops.GetAlg()), "", privateKey, publicKey, 1, keystore)
		DB.Where(&models.Keys{
			KeyName:    opt.Name,
			KeyVersion: 1,
			Keystore:   keystore,
		}).First(&key)
	}
	return key
}

func CreateKey(keyName, keyAlg, keyUse string, privateKey, publicKey []byte, keyVersion int, keystore models.Keystore) {
	DB.Create(&models.Keys{
		KeyName:    keyName,
		KeyVersion: keyVersion,
		KeyAlg:     keyAlg,
		KeyUse:     keyUse,
		PrivateKey: helper.ToHex(privateKey),
		PublicKey:  helper.ToHex(publicKey),
		Keystore:   keystore,
	})
}

func RotateKey(key models.Keys, privateKey, publicKey []byte) {
	key.PrivateKey = helper.ToHex(privateKey)
	key.PublicKey = helper.ToHex(publicKey)
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

func DeleteKey(username, token, keyName string, keyVersion int) {
	var keystore models.Keystore = GetOrCreateKeystore(username, token)
	//TODO I need to read the GORM documentation because the following is shitty
	if keyVersion >= 0 {
		DB.Delete(&models.Keys{}, models.Keys{
			KeyName:    keyName,
			Keystore:   keystore,
			KeyVersion: keyVersion,
		})
	} else {
		DB.Delete(&models.Keys{}, models.Keys{
			KeyName:  keyName,
			Keystore: keystore,
		})
	}
}
