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


## Endpoints:

### /rotate

#### Consumes
    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO ROTATE"}
#### Response
    {"creationdate": "UNIX NANO", "keyname": "KEYNAME", "keyversion": 0, "publickey": "HEX ENCODED"}

### /get/key

#### Consumes
    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY NAME", "keyversion": Key Version or -1 for the most recent one}
#### Response
    {"creationdate": "UNIX NANO", "keyname": "KEYNAME", "keyversion": 0, "publickey": "HEX ENCODED"}

### /get/keys

#### Consumes
    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY FROM WHICH TO RECEIVE ALL VERSIONS"}
#### Response
    [{"creationdate": "UNIX NANO", "keyname": "KEYNAME", "keyversion": 0, "publickey": "HEX ENCODED"}]

### /create/key

#### Consumes
    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keytype": "SEE LIST", "keyname": "KEYNAME", "keyversion": 0, "keysize": keysize for RSA, "keycurve": "Curve for ECC"}
#### Response
    {"creationdate": "UNIX NANO", "keyname": "KEYNAME", "keyversion": 0, "publickey": "HEX ENCODED"}

### /create/keystore
#### Consumes
    {"username": "YOUR USERNAME", "token": "YOUR TOKEN"}
#### Response
    {"message": "Keystore Created"}

### /create/user
#### Consumes
    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "newusername": "NEW USERNAME", "newtoken": "NEW TOKEN"}
#### Response
    {"message": "User {NEW USERNAME} created"}

### /sign
#### Consumes
    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO BE USED", "keyversion": Key Version or -1 for the most recent one, "msg": "MESSAGE AS HEX"}
#### Response
    {"message": "HEX ENCODED SIGNATURE"}

### /encrypt
#### Consumes
    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO BE USED", "keyversion": Key Version or -1 for the most recent one, "msg": "MESSAGE AS HEX"}
#### Response
    {"message": "HEX ENCODED"}

### /decrypt
#### Consumes
    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO BE USED", "keyversion": Key Version or -1 for the most recent one, "msg": "MESSAGE AS HEX"}
#### Response
    {"message": "HEX ENCODED"}

### /remove/key
#### Consumes
    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "keyname": "KEY TO BE DELETED", "keyversion": keyversion to be deleted (in case to delete all version, use -1), "deletiontime": "Timestamp as UnixNano(int64) when the key shall be delete, use -1 to delete it directly"}
#### Response
    {"message": "OK"}

### /remove/user
#### Consumes
    {"username": "YOUR USERNAME", "token": "YOUR TOKEN", "deleteusername": "USER TO BE REMOVED"}
#### Response
    {"message": "OK"}

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

## Problems

Problems on saving the private_key in DB drop the `keys_private_key_key` constraints in the keys table