package database

import (
	"github.com/labstack/gommon/log"
	"lars-krieger.de/pseudo-kms/database/models"
	"strconv"
)

func GetOrCreateKeystore(username, token string) models.Keystore {
	var accUser models.AccessUser = GetUser(username, token)
	var keystore models.Keystore
	DB.Model(&models.Keystore{}).Where(&models.Keystore{
		AccessUserId: strconv.FormatUint(uint64(accUser.ID), 10),
	}).First(&keystore)

	if keystore.AccessUserId == strconv.FormatUint(uint64(accUser.ID), 10) {
		log.Printf("KeyStore: %v, User: %v", keystore, accUser)
		return keystore
	}
	keystore = models.Keystore{
		AccessUserId: strconv.FormatUint(uint64(accUser.ID), 10),
	}
	DB.Create(&keystore)
	return keystore
}
