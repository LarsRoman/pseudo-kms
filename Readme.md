# Pseudo KMS

This project is designed to emulate a KMS.
It must not be used on a productive environment

Each User has one Keystore which includes all keys

```mermaid
graph LR
USER -- 1 : 1 --> KEYSTORE
KEYSTORE -- 1 : N --> KEYS
```

# Rest

Following REST Calles are included by now:

	router.POST("/rotate", postRotateKey)
	router.POST("/create/key", postCreateKey)
	router.POST("/create/keystore", postCreateKeyStore)
	router.POST("/create/user", postCreateUser)
	router.POST("/sign", postSignWithKey)
	router.POST("/encrypt", postEncrypt)
	router.POST("/decrypt", postDecrypt)
	router.POST("/get/key", getKey)
	router.POST("/get/keys", getKeys)
	router.POST("/remove/key", postDeleteKey)
	router.POST("/remove/user", postDeleteUser)


## Following JSON is consumed by the endpoints:

### /rotate

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO ROTATE"}

### /get/key

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY FROM WHICH TO RECEIVE CURRENT VERSION"}

### /get/keys

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY FROM WHICH TO RECEIVE ALL VERSIONS"}

### /create/key

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keytype": "SEE LIST", "keyname": "KEYNAME", "keyversion": 0}

### /create/keystore

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN"}

### /create/user

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "newusername": "NEW USERNAME", "newtoken": "NEW TOKEN"}

### /sign

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO BE USED", "msg": "MESSAGE AS HEX"}

### /encrypt

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO BE USED", "msg": "MESSAGE AS HEX"}

### /decrypt

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO BE USED", "msg": "MESSAGE AS HEX"}

### /remove/key

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO BE DELETED", "keyversion": keyversion to be deleted (in case to delete all version, use -1), "deletiontime": "Timestamp as UnixNano(int64) when the key shall be delete, use -1 to delete it directly"}

### /remove/user

    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "deleteusername": "USER TO BE REMOVED"}


## Implementation

|                  | RSA | ECC |
|------------------|-----|-----|
| /rotate          | YES | YES |
| /create/key      | YES | YES |
| /create/keystore | YES | YES |
| /create/user     | -   | -   |
| /sign            | YES | YES |
| /encrypt         | YES | YES |
| /decrypt         | YES | YES |
| /get/key         | YES | YES |
| /get/keys        | YES | YES |
| /delete/key      | YES | YES |


### RSA Supported "Key Types"

| Name                      | Planed | Supported/Implemented |
|---------------------------|--------|-----------------------|
| RSASSA_PSS_SHA_256        | YES    | NO                    |
| RSASSA_PSS_SHA_384        | YES    | NO                    |
| RSASSA_PSS_SHA_512        | YES    | NO                    |
| RSASSA_PKCS1_V1_5         | -      | YES                   |
| RSASSA_PKCS1_V1_5_SHA_256 | -      | YES                   |
| RSASSA_PKCS1_V1_5_SHA_384 | -      | YES                   |
| RSASSA_PKCS1_V1_5_SHA_512 | -      | YES                   |

### ECC Supported "Key Types"

| Name               | Planed | Supported/Implemented |
|--------------------|--------|-----------------------|
| ECDSA_P256         | -      | YES                   |
| ECDSA_P256_SHA_256 | -      | YES                   |
| ECDSA_P384_SHA_384 | -      | YES                   |
| ECDSA_P512_SHA_512 | -      | YES                   |

# Setup

1. Clone the repository
2. Edit the ENV file
3. Run `docker-compose build && docker-compose up`

## Change Config

If you want to change the config and redeploy the container
* Run `docker-compose down && docker-compose rm && docker-compose build && docker-compose up`