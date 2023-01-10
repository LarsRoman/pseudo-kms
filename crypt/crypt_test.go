package crypt

import (
	"lars-krieger.de/pseudo-kms/crypt/rsa"
	"lars-krieger.de/pseudo-kms/database/models"
	"testing"
)

func TestInterface(t *testing.T) {
	var r AsymmetricKeyOps = &rsa.RSA{}
	r.Bind(models.Keys{
		KeyName:    "Test1",
		KeyVersion: 1,
		KeyAlg:     "RSASSA_PKCS1_V1_5",
		KeySize:    1024,
		KeyUse:     "ENC",
	})
	priv, pub := r.Create()
	if len(pub) == 0 || len(priv) == 0 {
		t.Errorf("Interface to RSA was not successful. "+
			"Private Key or public Key were not created. Priv %v, Pub %v", priv, pub)
	}
}
