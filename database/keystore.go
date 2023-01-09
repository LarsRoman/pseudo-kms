package database

import (
	"lars-krieger.de/pseudo-kms/database/models"
)

func GetOrCreateKeystore(username, token string) models.Keystore {
	var keystore models.Keystore
	DB.FirstOrCreate(&keystore, &models.Keystore{
		AccessUser: GetUser(username, token),
	})
	return keystore
}
