package database

import (
	"lars-krieger.de/pseudo-kms/database/models"
	"strconv"
)

func DeleteKeyKeyStoreUser(username string) {
	var user models.AccessUser
	DB.First(&user, models.AccessUser{
		Name: username,
	})
	var keystore models.Keystore
	DB.Model(&models.Keystore{}).Where(&models.Keystore{
		AccessUserId: strconv.FormatUint(uint64(user.ID), 10),
	}).First(&keystore)

	DB.Delete(&models.Keys{Keystore: strconv.FormatUint(uint64(keystore.ID), 10)})
	DB.Delete(&keystore)
	DB.Delete(&user)
}
