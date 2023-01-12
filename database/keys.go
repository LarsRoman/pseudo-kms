package database

import (
	"github.com/jinzhu/gorm"
	"lars-krieger.de/pseudo-kms/crypt"
	"lars-krieger.de/pseudo-kms/crypt/helper"
	"lars-krieger.de/pseudo-kms/database/models"
	"time"
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
		return CreateKey(opt.Name, ops.GetAlg(), "encryption/signing", privateKey, publicKey, 1, keystore)
	}
	return key
}

func CreateKey(keyName, keyAlg, keyUse string, privateKey, publicKey []byte, keyVersion int, keystore models.Keystore) models.Keys {
	var key models.Keys = models.Keys{
		KeyName:    keyName,
		KeyVersion: keyVersion,
		KeyAlg:     keyAlg,
		KeyUse:     keyUse,
		PrivateKey: helper.ToHex(privateKey),
		PublicKey:  helper.ToHex(publicKey),
		Keystore:   keystore,
	}
	DB.Create(&key)
	return key
}

func RotateKey(key models.Keys, privateKey, publicKey []byte) models.Keys {
	key.PrivateKey = helper.ToHex(privateKey)
	key.PublicKey = helper.ToHex(publicKey)
	key.KeyVersion = key.KeyVersion + 1
	key.DeletedAt = nil
	DB.Create(&key)
	return key
}

func GetCurrentKey(username, token, keyName string) models.Keys {
	var keystore models.Keystore = GetOrCreateKeystore(username, token)
	var key models.Keys
	DB.Order("KeyVersion desc").Where(&models.Keys{
		KeyName:  keyName,
		Keystore: keystore,
	}).First(&key)
	return key
}

func GetKey(username, token, keyName string, keyVersion int) models.Keys {
	if keyVersion == -1 {
		return GetCurrentKey(username, token, keyName)
	}
	var keystore models.Keystore = GetOrCreateKeystore(username, token)
	var key models.Keys
	DB.Order("KeyVersion desc").Order("id").Where(&models.Keys{
		KeyName:    keyName,
		Keystore:   keystore,
		KeyVersion: keyVersion,
	}).First(&key)
	return key
}

func GetAllKeys(username, token, keyName string) []models.Keys {
	var keystore models.Keystore = GetOrCreateKeystore(username, token)
	//TODO I need to read the GORM documentation because the following is shitty
	var keyArr, keys []models.Keys
	DB.Where(&models.Keys{
		KeyName:  keyName,
		Keystore: keystore,
	}).Find(&keyArr)
	var now time.Time = time.Now()
	for _, key := range keyArr {
		if key.DeletedAt == nil || key.DeletedAt.After(now) {
			keys = append(keys, key)
		}
	}
	return keys
}

func DeleteKey(username, token, keyName string, keyVersion int, deletionTime int64) {
	var keystore models.Keystore = GetOrCreateKeystore(username, token)
	if deletionTime != -1 {
		var deletionDate time.Time = time.Unix(0, deletionTime)
		if keyVersion == -1 {
			DB.Model(&models.Keys{}).Where(&models.Keys{
				KeyName:  keyName,
				Keystore: keystore,
			}).Select("*").Update(models.Keys{
				Model: gorm.Model{
					DeletedAt: &deletionDate,
				},
			})
		} else {
			DB.Model(&models.Keys{}).Where(&models.Keys{
				KeyName:    keyName,
				Keystore:   keystore,
				KeyVersion: keyVersion,
			}).Select("*").Update(models.Keys{
				Model: gorm.Model{
					DeletedAt: &deletionDate,
				},
			})
		}
	} else {
		if keyVersion == -1 {
			DB.Delete(&models.Keys{}, models.Keys{
				KeyName:  keyName,
				Keystore: keystore,
			})
		} else {
			DB.Delete(&models.Keys{}, models.Keys{
				KeyName:    keyName,
				Keystore:   keystore,
				KeyVersion: keyVersion,
			})
		}
	}
}
