package rest

import (
	"fmt"
	"github.com/gin-gonic/gin"
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

	var ops crypt.AsymmetricKeyOps = detectECCorRSA(newKey.AsymmetricKeyType)
	if ops == nil {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "KeyType was not found"})
		return
	}
	ops.Bind(models.Keys{
		KeyName:    newKey.KeyName,
		KeyVersion: newKey.KeyVersion,
		KeyAlg:     newKey.AsymmetricKeyType,
		KeySize:    newKey.KeySize,
		KeyCurve:   newKey.KeyCurve,
		KeyUse:     "encryption/signing",
	})
	database.GetOrCreateKey(ops, newKey.GinUser.Username, newKey.GinUser.Token)
	c.IndentedJSON(http.StatusCreated, gin.H{"message": "RSA Key was Created"})
}

func postSignWithKey(c *gin.Context) {
	var signWithKey structs.GinKey
	if err := c.BindJSON(&signWithKey); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	var key models.Keys = database.GetCurrentKey(signWithKey.GinUser.Username, signWithKey.GinUser.Token, signWithKey.KeyName)
	var ops crypt.AsymmetricKeyOps = detectECCorRSA(key.KeyAlg)
	if ops == nil {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "KeyType was not found"})
		return
	}
	var hexSignature string = ops.Sign(signWithKey.Message)
	c.IndentedJSON(http.StatusOK, gin.H{"message": hexSignature})
}

func postEncrypt(c *gin.Context) {
	var signWithKey structs.GinKey
	if err := c.BindJSON(&signWithKey); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	var key models.Keys = database.GetCurrentKey(signWithKey.GinUser.Username, signWithKey.GinUser.Token, signWithKey.KeyName)
	var ops crypt.AsymmetricKeyOps = detectECCorRSA(key.KeyAlg)
	if ops == nil {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "KeyType was not found"})
		return
	}
	var hexEncrypt string = ops.Encrypt(signWithKey.Message)
	c.IndentedJSON(http.StatusOK, gin.H{"message": hexEncrypt})
}

func postDecrypt(c *gin.Context) {
	var ginKey structs.GinKey
	if err := c.BindJSON(&ginKey); err != nil {
		log.Errorf("Failed to bind JSON: %s", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}
	var key models.Keys = database.GetCurrentKey(ginKey.GinUser.Username, ginKey.GinUser.Token, ginKey.KeyName)
	var ops crypt.AsymmetricKeyOps = detectECCorRSA(key.KeyAlg)
	if ops == nil {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "KeyType was not found"})
		return
	}
	var hexDecrypt string = ops.Decrypt(ginKey.Message)
	c.IndentedJSON(http.StatusOK, gin.H{"message": hexDecrypt})
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

func detectECCorRSA(keyAlg string) crypt.AsymmetricKeyOps {
	if strings.Contains(keyAlg, helper.RSA.ToString()) {
		return &rsa.RSA{}
	} else if strings.Contains(keyAlg, helper.ECC.ToString()) {
		return &ecc.ECC{}
	}
	return nil
}
