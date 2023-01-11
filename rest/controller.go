package rest

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/labstack/gommon/log"
	"lars-krieger.de/pseudo-kms/crypt"
	"lars-krieger.de/pseudo-kms/crypt/ecc"
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
	router.POST("/remove/key", postDeleteKey)
	router.POST("/remove/user", postDeleteUser)

	err := router.Run(fmt.Sprintf(":%d", port))
	//err := router.Run(fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Errorf("Could not start GIN %s", err.Error())
	}
}

func getKey(c *gin.Context) {
	var usedJSONStruct structs.GinKey
	if err := c.ShouldBindBodyWith(&usedJSONStruct, binding.JSON); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	usedJSONStruct.GinUser = bindGinUser(c)
	var key models.Keys = database.GetCurrentKey(
		usedJSONStruct.GinUser.Username,
		usedJSONStruct.GinUser.Token,
		usedJSONStruct.KeyName,
	)
	c.IndentedJSON(http.StatusOK, gin.H{"message": fmt.Sprintf("%s", key.PublicKey)})
}

func postDeleteKey(c *gin.Context) {
	var usedJSONStruct structs.GinDeleteKey
	if err := c.ShouldBindBodyWith(&usedJSONStruct, binding.JSON); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	usedJSONStruct.GinUser = bindGinUser(c)
	database.DeleteKey(
		usedJSONStruct.GinUser.Username,
		usedJSONStruct.GinUser.Token,
		usedJSONStruct.KeyName,
		usedJSONStruct.KeyVersion,
	)
	c.IndentedJSON(http.StatusOK, gin.H{"message": "OK"})
}

func postDeleteUser(c *gin.Context) {
	var usedJSONStruct structs.GinDeleteUser
	if err := c.ShouldBindBodyWith(&usedJSONStruct, binding.JSON); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	usedJSONStruct.GinUser = bindGinUser(c)
	database.DeleteUser(
		usedJSONStruct.GinUser.Username,
		usedJSONStruct.GinUser.Token,
		usedJSONStruct.DeleteUsername,
	)
	c.IndentedJSON(http.StatusOK, gin.H{"message": "OK"})
}

func postRotateKey(c *gin.Context) {
	var usedJSONStruct structs.GinKey
	if err := c.ShouldBindBodyWith(&usedJSONStruct, binding.JSON); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	usedJSONStruct.GinUser = bindGinUser(c)
	var currentKey models.Keys = database.GetCurrentKey(
		usedJSONStruct.GinUser.Username,
		usedJSONStruct.GinUser.Token,
		usedJSONStruct.KeyName,
	)
	var ops crypt.AsymmetricKeyOps = detectECCorRSA(currentKey.KeyAlg)
	if ops == nil {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "KeyType was not found"})
		return
	}
	ops.Bind(currentKey)
	privateKey, publicKey := ops.Create()
	database.RotateKey(currentKey, privateKey, publicKey)
	c.IndentedJSON(http.StatusCreated, gin.H{"message": fmt.Sprintf("%s Key was Created", ops.GetAlg())})
}

func postCreateKeyStore(c *gin.Context) {
	var usedJSONStruct structs.GinUser
	if err := c.ShouldBindBodyWith(&usedJSONStruct, binding.JSON); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	database.GetOrCreateKeystore(usedJSONStruct.Username, usedJSONStruct.Token)
	c.IndentedJSON(http.StatusCreated, gin.H{"message": "Keystore created"})
}

func postCreateKey(c *gin.Context) {
	var usedJSONStruct structs.GinCreateKey
	if err := c.ShouldBindBodyWith(&usedJSONStruct, binding.JSON); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	usedJSONStruct.GinUser = bindGinUser(c)
	var ops crypt.AsymmetricKeyOps = detectECCorRSA(usedJSONStruct.AsymmetricKeyType)
	if ops == nil {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "KeyType was not found"})
		return
	}
	ops.Bind(models.Keys{
		KeyName:    usedJSONStruct.KeyName,
		KeyVersion: usedJSONStruct.KeyVersion,
		KeyAlg:     usedJSONStruct.AsymmetricKeyType,
		KeySize:    usedJSONStruct.KeySize,
		KeyCurve:   usedJSONStruct.KeyCurve,
		KeyUse:     "encryption/signing",
	})
	database.GetOrCreateKey(ops, usedJSONStruct.GinUser.Username, usedJSONStruct.GinUser.Token)
	c.IndentedJSON(http.StatusCreated, gin.H{"message": "RSA Key was Created"})
}

func postSignWithKey(c *gin.Context) {
	var usedJSONStruct structs.GinKey
	if err := c.ShouldBindBodyWith(&usedJSONStruct, binding.JSON); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	usedJSONStruct.GinUser = bindGinUser(c)
	var key models.Keys = database.GetCurrentKey(
		usedJSONStruct.GinUser.Username,
		usedJSONStruct.GinUser.Token,
		usedJSONStruct.KeyName,
	)
	var ops crypt.AsymmetricKeyOps = detectECCorRSA(key.KeyAlg)
	if ops == nil {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "KeyType was not found"})
		return
	}
	var hexSignature string = ops.Sign(usedJSONStruct.Message)
	c.IndentedJSON(http.StatusOK, gin.H{"message": hexSignature})
}

func postEncrypt(c *gin.Context) {
	var usedJSONStruct structs.GinKey
	if err := c.ShouldBindBodyWith(&usedJSONStruct, binding.JSON); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	usedJSONStruct.GinUser = bindGinUser(c)
	var key models.Keys = database.GetCurrentKey(
		usedJSONStruct.GinUser.Username,
		usedJSONStruct.GinUser.Token,
		usedJSONStruct.KeyName,
	)
	var ops crypt.AsymmetricKeyOps = detectECCorRSA(key.KeyAlg)
	if ops == nil {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "KeyType was not found"})
		return
	}
	var hexEncrypt string = ops.Encrypt(usedJSONStruct.Message)
	c.IndentedJSON(http.StatusOK, gin.H{"message": hexEncrypt})
}

func postDecrypt(c *gin.Context) {
	var usedJSONStruct structs.GinKey
	if err := c.ShouldBindBodyWith(&usedJSONStruct, binding.JSON); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	usedJSONStruct.GinUser = bindGinUser(c)
	var key models.Keys = database.GetCurrentKey(
		usedJSONStruct.GinUser.Username,
		usedJSONStruct.GinUser.Token,
		usedJSONStruct.KeyName,
	)
	var ops crypt.AsymmetricKeyOps = detectECCorRSA(key.KeyAlg)
	if ops == nil {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "KeyType was not found"})
		return
	}
	var hexDecrypt string = ops.Decrypt(usedJSONStruct.Message)
	c.IndentedJSON(http.StatusOK, gin.H{"message": hexDecrypt})
}

func postCreateUser(c *gin.Context) {
	var usedJSONStruct structs.GinNewUser
	if err := c.ShouldBindBodyWith(&usedJSONStruct, binding.JSON); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	usedJSONStruct.GinUser = bindGinUser(c)
	if isAuth, _ := database.GetAndCheckUser(usedJSONStruct.GinUser.Username, usedJSONStruct.GinUser.Token); isAuth {
		database.CreateUser(usedJSONStruct.Username, usedJSONStruct.Token, false)
		c.IndentedJSON(http.StatusCreated, gin.H{"message": fmt.Sprintf("User %s created", usedJSONStruct.Username)})
	} else {
		c.IndentedJSON(http.StatusForbidden, gin.H{"message": "New User could not be created"})
	}
}

func detectECCorRSA(keyAlg string) crypt.AsymmetricKeyOps {
	if strings.Contains(keyAlg, helper.RSA.ToString()) {
		return &rsa.RSA{}
	} else if strings.Contains(keyAlg, helper.ECC.ToString()) {
		return &ecc.ECC{}
	}
	return nil
}

func bindGinUser(c *gin.Context) structs.GinUser {
	var newUser structs.GinUser
	if err := c.ShouldBindBodyWith(&newUser, binding.JSON); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return structs.GinUser{}
	}
	return newUser
}
