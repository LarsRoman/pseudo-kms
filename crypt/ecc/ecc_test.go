package ecc

import (
	"crypto/elliptic"
	"gitlab.com/elktree/ecc"
	"lars-krieger.de/pseudo-kms/crypt/helper"
	"lars-krieger.de/pseudo-kms/database/models"
	"testing"
)

var privateKeyMemHex = "2d2d2d2d2d424547494e2045432050524956415445204b45592d2d2d2d2d0a" +
	"4d4863434151454549424d306379694162446e7030413655595545767358624c334c7176434875754" +
	"d4234793046326b317348716f416f4743437147534d34390a417745486f5551445167414551394864" +
	"43697a67793872523078436a4d73484d7369384d6d397077426c72524b77322f4a2b7576566e75317" +
	"7544c37696266650a4f36444d746c663967566842693679437943393251714d42726b6c6c73365070" +
	"4d673d3d0a2d2d2d2d2d454e442045432050524956415445204b45592d2d2d2d2d0a"

var publicKeyMemHex = "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b774" +
	"57759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741455139486443697a6779" +
	"3872523078436a4d73484d7369384d6d3970770a426c72524b77322f4a2b7576566e753177544c376" +
	"96266654f36444d746c663967566842693679437943393251714d42726b6c6c733650704d673d3d0a" +
	"2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a"

var msg = "I am a secret message: You are cute!"

func TestCreate(t *testing.T) {
	var ecc ECC
	priv, pub := ecc.Create()

	if len(priv) == 0 {
		t.Errorf("Private Key was not generated: %v", priv)
		return
	}
	if len(pub) == 0 {
		t.Errorf("Public Key was not generated: %v", pub)
		return
	}
	t.Logf("Keys were generted")
}

func TestGetAlg(t *testing.T) {
	var ecc ECC = ECC{
		AsymmetricOpt: helper.AsymmetricOpt{
			KeyTypes: "TEST",
		},
	}
	if ecc.GetAlg() != "TEST" {
		t.Errorf("Alg is not matching: expected: %s, actual: %s", "TEST", ecc.GetAlg())
		return
	}
	t.Logf("AlgTest was successful expected: %s, actual: %s", "TEST", ecc.GetAlg())
}

func TestGetInfo(t *testing.T) {
	var asymOpt helper.AsymmetricOpt = helper.AsymmetricOpt{
		Name:        "TEST1",
		Version:     100,
		WriteToFile: false,
		Hash:        "SHA1",
		KeyTypes:    "TEST2",
	}
	var r ECC = ECC{
		AsymmetricOpt: asymOpt,
	}
	if r.AsymmetricOpt != asymOpt {
		t.Errorf("AsymmetricOpt are not matching: expected: %v, actual: %v", asymOpt, r.AsymmetricOpt)
		return
	}
	t.Logf("AsymmetricOptTest was successful expected: %v, actual: %v", asymOpt, r.AsymmetricOpt)
}

func TestKeysMem(t *testing.T) {
	var privateKey ecc.PrivateKey = *MemToPrivateKey(helper.FromHex(privateKeyMemHex))
	var publicKey ecc.PublicKey = *MemToPublicKey(helper.FromHex(publicKeyMemHex))
	if helper.ToHex(PrivateKeyToMem(&privateKey)) != privateKeyMemHex {
		t.Errorf("Hex to Mem to Private key to mem to hex failed: expected: %v, actual: %v",
			privateKeyMemHex, helper.ToHex(PrivateKeyToMem(&privateKey)))
		return
	}
	if helper.ToHex(PublicKeyToMem(&publicKey)) != publicKeyMemHex {
		t.Errorf("Hex to Mem to Public key to mem to hex failed: expected: %v, actual: %v",
			publicKeyMemHex, helper.ToHex(PublicKeyToMem(&publicKey)))
		return
	}
}

func TestBind(t *testing.T) {
	var key models.Keys = models.Keys{
		KeyName:    "Test1",
		KeyVersion: 1,
		KeyAlg:     "ECDSA_P384_SHA_384",
		KeyCurve:   "P384",
		KeyUse:     "ENC",
		PrivateKey: privateKeyMemHex,
		PublicKey:  publicKeyMemHex,
	}
	var e ECC
	e.Bind(key)
	if e.Curve != elliptic.P384() ||
		helper.ToHex(PrivateKeyToMem(&e.PrivateKey)) != privateKeyMemHex ||
		helper.ToHex(PublicKeyToMem(&e.PublicKey)) != publicKeyMemHex ||
		e.AsymmetricOpt.Name != key.KeyName ||
		e.AsymmetricOpt.KeyTypes != string(helper.RSAKeyTypes(key.KeyAlg)) ||
		e.AsymmetricOpt.Version != key.KeyVersion ||
		e.AsymmetricOpt.Hash != helper.Hashes(helper.SHA384) {
		t.Errorf("Bind was not successful. ECC: %v, Used Key: %v", e, key)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	var e ECC
	e.PublicKey = *MemToPublicKey(helper.FromHex(publicKeyMemHex))
	var encmsg string = e.Encrypt(helper.ToHex([]byte(msg)))

	e.PrivateKey = *MemToPrivateKey(helper.FromHex(privateKeyMemHex))
	var msg2 string = string(helper.FromHex(e.Decrypt(encmsg)))

	if msg2 != msg {
		t.Errorf("Expected %s, Actual %s", msg, msg2)
	}
}
