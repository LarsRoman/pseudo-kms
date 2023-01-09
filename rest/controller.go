package rest

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/labstack/gommon/log"
	"lars-krieger.de/pseudo-kms/crypt/helper"
	"lars-krieger.de/pseudo-kms/crypt/rsa"
	"lars-krieger.de/pseudo-kms/database"
	"lars-krieger.de/pseudo-kms/database/models"
	"lars-krieger.de/pseudo-kms/rest/structs"
	"net/http"
	"strings"
)

func Router(host string, port int) {
	router := gin.Default()
	router.POST("/rotate", postRotateKey)
	router.POST("/create/key", postCreateKey)
	router.POST("/create/keystore", postCreateKeyStore)
	router.POST("/create/user", postCreateUser)
	router.POST("/sign", postSignWithKey)
	router.POST("/encrypt", postEncrypt)
	router.POST("/decrypt", postDecrypt)
	router.GET("/get/key", getKey)

	err := router.Run(fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Errorf("Could not start GIN %s", err.Error())
	}
}

func getKey(c *gin.Context) {
	var ginKey structs.GinKey
	if err := c.BindJSON(&ginKey); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	var key models.Keys = database.GetCurrentKey(ginKey.GinUser.Username, ginKey.GinUser.Token, ginKey.KeyName)
	c.IndentedJSON(http.StatusOK, gin.H{"message": fmt.Sprintf("%s", key.PublicKey)})
}

func postRotateKey(c *gin.Context) {
	var ginKey structs.GinKey
	if err := c.BindJSON(&ginKey); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	var currentKey models.Keys = database.GetCurrentKey(ginKey.GinUser.Username, ginKey.GinUser.Token, ginKey.KeyName)
	if strings.Contains(currentKey.KeyAlg, helper.RSA.ToString()) {
		var newRSA = rsa.RSA{
			KeySize: currentKey.KeySize,
			AsymmetricOpt: helper.AsymmetricOpt{
				Name:        currentKey.KeyName,
				Version:     currentKey.KeyVersion,
				WriteToFile: false,
			},
		}
		privateKey, publicKey := newRSA.Create()
		database.RotateKey(currentKey, privateKey, publicKey)
		c.IndentedJSON(http.StatusCreated, gin.H{"message": "RSA Key was Created"})
	} else if strings.Contains(currentKey.KeyAlg, helper.ECC.ToString()) {

	}
}

func postCreateKeyStore(c *gin.Context) {
	var user structs.GinUser
	if err := c.BindJSON(&user); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	database.GetOrCreateKeystore(user.Username, user.Token)
	c.IndentedJSON(http.StatusCreated, gin.H{"message": "Keystore created"})
}

func postCreateKey(c *gin.Context) {
	var newKey structs.GinCreateKey
	if err := c.BindJSON(&newKey); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	if strings.Contains(newKey.AsymmetricKeyType.ToString(), helper.RSA.ToString()) {
		var newRSA = rsa.RSA{
			KeySize: 0,
			AsymmetricOpt: helper.AsymmetricOpt{
				Name:        newKey.KeyName,
				Version:     newKey.KeyVersion,
				WriteToFile: false,
			},
		}
		database.GetOrCreateKey(newRSA, newKey.GinUser.Username, newKey.GinUser.Token)
		c.IndentedJSON(http.StatusCreated, gin.H{"message": "RSA Key was Created"})
	} else if strings.Contains(newKey.AsymmetricKeyType.ToString(), helper.ECC.ToString()) {

	} else {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "KeyType was not Found. Please use RSA or ECC"})
	}

}

func postSignWithKey(c *gin.Context) {
	var signWithKey structs.GinKey
	if err := c.BindJSON(&signWithKey); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	var key models.Keys = database.GetCurrentKey(signWithKey.GinUser.Username, signWithKey.GinUser.Token, signWithKey.KeyName)
	if strings.Contains(key.KeyAlg, helper.RSA.ToString()) {
		var newRSA = rsa.RSA{
			PrivateKey: *rsa.MemToPrivateKey(helper.FromHex(key.PrivateKey)),
		}
		var hexSignature string
		if signWithKey.Hash != " " && signWithKey.Hash != "" {
			hexSignature = newRSA.SignWithHash(signWithKey.Message, signWithKey.Hash)
		} else {
			hexSignature = newRSA.Sign(signWithKey.Message)
		}
		c.IndentedJSON(http.StatusOK, gin.H{"message": hexSignature})
	} else if strings.Contains(key.KeyAlg, helper.ECC.ToString()) {

	} else {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "KeyType was not Found. Please use RSA or ECC"})
	}
}

func postEncrypt(c *gin.Context) {
	var signWithKey structs.GinKey
	if err := c.BindJSON(&signWithKey); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	var key models.Keys = database.GetCurrentKey(signWithKey.GinUser.Username, signWithKey.GinUser.Token, signWithKey.KeyName)
	if strings.Contains(key.KeyAlg, helper.RSA.ToString()) {
		var newRSA = rsa.RSA{
			PrivateKey: *rsa.MemToPrivateKey(helper.FromHex(key.PrivateKey)),
			PublicKey:  *rsa.MemToPublicKey(helper.FromHex(key.PublicKey)),
		}
		var hexEncrypt string = newRSA.Encrypt(signWithKey.Message)
		c.IndentedJSON(http.StatusOK, gin.H{"message": hexEncrypt})
	} else if strings.Contains(key.KeyAlg, helper.ECC.ToString()) {

	} else {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "KeyType was not Found. Please use RSA or ECC"})
	}
}

func postDecrypt(c *gin.Context) {
	var ginKey structs.GinKey
	if err := c.BindJSON(&ginKey); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	var key models.Keys = database.GetCurrentKey(ginKey.GinUser.Username, ginKey.GinUser.Token, ginKey.KeyName)
	if strings.Contains(key.KeyAlg, helper.RSA.ToString()) {
		var newRSA = rsa.RSA{
			PrivateKey: *rsa.MemToPrivateKey(helper.FromHex(key.PrivateKey)),
			PublicKey:  *rsa.MemToPublicKey(helper.FromHex(key.PublicKey)),
		}
		var hexDecrypt string = newRSA.Decrypt(ginKey.Message)
		c.IndentedJSON(http.StatusOK, gin.H{"message": hexDecrypt})
	} else if strings.Contains(key.KeyAlg, helper.ECC.ToString()) {

	} else {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "KeyType was not Found. Please use RSA or ECC"})
	}
}

func postCreateUser(c *gin.Context) {
	var newUser structs.GinNewUser
	if err := c.BindJSON(&newUser); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	if isAuth, _ := database.GetAndCheckUser(newUser.GinUser.Username, newUser.GinUser.Token); isAuth {
		database.CreateUser(newUser.Username, newUser.Token, false)
		c.IndentedJSON(http.StatusCreated, gin.H{"message": fmt.Sprintf("User %s created", newUser.Username)})
	} else {
		c.IndentedJSON(http.StatusForbidden, gin.H{"message": "New User could not be created"})
	}
}
