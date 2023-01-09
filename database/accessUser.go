package database

import (
	"encoding/base64"
	"github.com/labstack/gommon/log"
	"lars-krieger.de/pseudo-kms/crypt/helper"
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
		var users models.AccessUser
		DB.First(users, models.AccessUser{
			Name: username,
		})
		return users
	}
	log.Infof("User %s is not a power user", username)
	return models.AccessUser{}
}

func GetAndCheckUser(username, token string) (bool, models.AccessUser) {
	if CheckPassword(username, token) && CheckPowerUser(username) {
		var users models.AccessUser
		DB.First(users, models.AccessUser{
			Name: username,
		})
		return true, users
	}
	log.Infof("User %s is not a power user", username)
	return false, models.AccessUser{}
}

func CreateUser(username, token string, powerUser bool) {
	DB.Create(&models.AccessUser{
		Name:      username,
		Token:     createTokenHash(token),
		PowerUser: powerUser,
	})
}

func DeleteUser(username, token string, usernameToDelete string) {
	if username == usernameToDelete {
		log.Infof("You are not allowed to delete your own user. Please contact support")
	}
	if CheckPassword(username, token) && CheckPowerUser(username) {
		DB.Delete(&models.AccessUser{
			Name: usernameToDelete,
		})
	} else {
		log.Infof("%s is not authorized to delete another user", username)
	}
}

func CheckPowerUser(username string) bool {
	var user = DB.Find(&models.AccessUser{Name: username, PowerUser: true})
	if user.Error != nil {
		log.Errorf("Poweruser was not valid: %s", user.Error.Error())
		return false
	}
	if rows, err := user.Rows(); err != nil {
		log.Errorf("Poweruser Rows were not valid: %s", user.Error.Error())
		defer rows.Close()
		return false
	} else {
		defer rows.Close()
		var userPuffer models.AccessUser
		for rows.Next() {
			if err := DB.ScanRows(rows, &userPuffer); err == nil {
				if username == userPuffer.Name {
					return userPuffer.PowerUser
				}
			}
		}
	}
	return false
}

func CheckPassword(username, token string) bool {
	var user = DB.Find(&models.AccessUser{Name: username, Token: createTokenHash(token)})
	if user.Error != nil {
		log.Errorf("User or Token was not valid: %s", user.Error.Error())
		return false
	}
	if rows, err := user.Rows(); err != nil {
		log.Errorf("User or Token Rows were not valid: %s", user.Error.Error())
		defer rows.Close()
		return false
	} else {
		defer rows.Close()
		var userPuffer models.AccessUser
		for rows.Next() {
			if err := DB.ScanRows(rows, &userPuffer); err == nil {
				if username == userPuffer.Name {
					return true
				}
			}
		}
	}
	return false
}

func createTokenHash(token string) string {
	var hasher = helper.SHA1.HashString()
	hasher.Write([]byte(token))
	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}
