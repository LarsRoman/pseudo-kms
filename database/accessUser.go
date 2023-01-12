package database

import (
	"github.com/labstack/gommon/log"
	"lars-krieger.de/pseudo-kms/database/models"
)

func GetAllUsers(username, token string) []models.AccessUser {
	if CheckPassword(username, token) && CheckPowerUser(username) {
		var users []models.AccessUser
		DB.Find(&users)
		return users
	}
	log.Infof("User %s is not a power user", username)
	return nil
}

func GetUser(username, token string) models.AccessUser {
	if CheckPassword(username, token) {
		var user models.AccessUser
		DB.First(&user, models.AccessUser{
			Name: username,
		})
		log.Info("User from DB: %v", user)
		return user
	}
	log.Infof("User %s is not a power user", username)
	return models.AccessUser{}
}

func GetAndCheckUser(username, token string) (bool, models.AccessUser) {
	if CheckPassword(username, token) && CheckPowerUser(username) {
		var user models.AccessUser
		DB.Where(&models.AccessUser{
			Name: username,
		}).First(&user)
		log.Info("User from DB: %v", user)
		return true, user
	}
	log.Infof("User %s is not a power user", username)
	return false, models.AccessUser{}
}

func CreateUser(username, token string, powerUser bool) {
	DB.Create(&models.AccessUser{
		Name:      username,
		Token:     createSecret(token),
		PowerUser: powerUser,
	})
}

func DeleteUser(username, token string, usernameToDelete string) {
	if username == usernameToDelete {
		log.Infof("You are not allowed to delete your own user. Please contact support")
		return
	}
	if CheckPassword(username, token) && CheckPowerUser(username) {
		DeleteKeyKeyStoreUser(usernameToDelete)
	} else {
		log.Infof("%s is not authorized to delete another user", username)
	}
}

func CheckPowerUser(username string) bool {
	var user models.AccessUser
	DB.Where(&models.AccessUser{
		Name:      username,
		PowerUser: true,
	}).First(&user)
	log.Info("PowerUser from DB: %v", user)
	if user.Name != username || !user.PowerUser {
		log.Errorf("Poweruser was not valid: %v", user)
		return false
	}
	return true
}

func CheckPassword(username, token string) bool {
	var user models.AccessUser
	DB.Where(&models.AccessUser{
		Name:  username,
		Token: createSecret(token),
	}).First(&user)
	log.Info("User from DB: %v", user)
	if user.Name != username || createSecret(token) != user.Token {
		log.Errorf("User or Token was not valid: %v", user)
		return false
	}
	return true
}

func createSecret(token string) string {
	//return base64.URLEncoding.EncodeToString([]byte(rsa.RSA_MASTER_KEY.Encrypt(helper.ToHex([]byte(token)))))
	return token
}
