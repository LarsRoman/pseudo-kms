package database

import "lars-krieger.de/pseudo-kms/database/models"

func DeleteKeyKeyStoreUser(username string) {
	DB.Delete(&models.Keys{Keystore: models.Keystore{
		AccessUser: models.AccessUser{
			Name: username,
		},
	}})
	DB.Delete(&models.Keystore{
		AccessUser: models.AccessUser{
			Name: username,
		},
	})
	DB.Delete(&models.AccessUser{
		Name: username,
	})
}
