# Pseudo KMS

This project is designed to emulate a KMS.
It must not be used on a productive environment


# Rest

Following REST Calles are included by now:

    router.POST("/rotate", postRotateKey)  
    router.POST("/create/key", postCreateKey)  
    router.POST("/create/keystore", postCreateKeyStore)  
    router.POST("/create/user", postCreateUser)  
    router.POST("/sign", postSignWithKey)  
    router.POST("/encrypt", postEncrypt)  
    router.POST("/decrypt", postDecrypt)  
    router.GET("/get/key", getKey)

## Following JSON is consumed by the endpoints:
### /rotate

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO ROTATE"}
### /create/key

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keytype": "RSA OR ECC", "keyops": "", "keyname": "KEYNAME", "keyversion": 0}

### /create/keystore

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN"}

### /create/user

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "newusername": "NEW USERNAME", "newtoken": "NEW TOKEN"}

### /sign

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO BE USED", "HASH": "USE HASH OR LEAVE BLANK WHEN SIGNING WITHOUT HASH", "msg": "MESSAGE AS HEX"}

### /encrypt

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO BE USED", "msg": "MESSAGE AS HEX"}

### /decrypt

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO BE USED", "msg": "MESSAGE AS HEX"}

## Implementation

|                |RSA                            |ECC                         |
|----------------|-------------------------------|-----------------------------|
|/rotate         |YES                               |NO           |
|/create/key|YES           |YES           |
|/create/keystore|YES|YES|
|/create/user|-|-|
|/sign|YES                               |NO           |
|/encrypt|YES                               |NO           |
|/decrypt|YES                               |NO           |
|/get/key|YES                               |YES|



# Setup

1. Clone the repository
2. Edit the ENV file
3. Run `docker-compose up`
