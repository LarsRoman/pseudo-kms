package rsa

import (
	"crypto/rsa"
	"lars-krieger.de/pseudo-kms/crypt/helper"
	"lars-krieger.de/pseudo-kms/database/models"
	"testing"
)

var privateKeyMemHex = "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2" +
	"d0a4d4949457041494241414b434151454173697367323179636c746f626c48506847744c624a713" +
	"850356a434d632f546b3248305736582b7757656b312f7478570a4c644879594c5847533651784f5" +
	"439574e745778477a2b5351667443646e44736238637159555669785544682f484d666c5476726f3" +
	"537585141376570456b6f0a567050735370304e554e66327a44742f58344a47646a454f69516d535" +
	"87136476b43527637347273394f64537457673977597135376955456147466b475736440a435a4f3" +
	"548335073525765435961554e55666d3652463668634d593364614e674c7867557053576a7368334" +
	"b514264496c665051704f37314b77426839526b570a43425a4945423169565733314c6b4d7771725" +
	"a50454e4b653053414b715075414f75506345306f6656674f36692b315a696662384e774569566e6f" +
	"56386375520a6f657a65757a3367365677457a5746532b43585a586176746961644b452f53396f596" +
	"8454577494441514142416f4942414232356f464f34306339424f46532b0a4f4a49334636554f6c41" +
	"4a396d7846466a4743714467614b3753737a41335576345a6a6e6242374364514474746543744e6e3" +
	"854692b6256356c726e7871446f0a476970542b6a6763555778446450436662476544686237596f32" +
	"546d6c6a4b6d6d66704831365a6a4b584f526448574366362b356c6e506c6e3130786f5a2f320a556" +
	"a442b513061643051625443544f473372624a704665644357303465776843647a7739747750466a6e" +
	"7176747541324c724f6b44566a67304e4830757845330a6142756e534e2f5234596e6338486c50346" +
	"973626b51432f484c43505a48534b56655a5163312b3065705877503365694d584d334349647a6537" +
	"6d53763141420a6c46484a7365656676645a6573554343694d2f7a746a41393136755a4d6e3042574" +
	"45932327a4c54787341584b337a76675432326a364c6c354c3171576259660a773861556b55454367" +
	"5945413436694e6f5155304c683730686a7361573575686f517a6430736f686375646b6454346f6d5" +
	"2525664743536644f53744348574f0a6a4a716751565132677a496d59655775433434374e52684b46" +
	"745855454b594f497049646166624d61414a55697549476c61386566556e6f6335467941556c460a7" +
	"0625670316a303562387849694a4a2b544747533473724c533770775131776e756253584f36367956" +
	"332f4978637541494b3971442f45436759454179466c570a4a65595a346668364766454f736631365" +
	"67a50442f4f6233557563586a386b784f7247794b767149333850345a377a794d78572b496c664a34" +
	"4c6c6d584b38330a325737373343463148735436646e496f3873396c6345346b53384c6a314141515" +
	"a5572326635544278586b536d5576756852594d6d30626e4272387552626b650a616d55687a6d4a79" +
	"6338435a696339656f6c3355307641544857344e5852514672774d2f6d454d43675945416e4770656" +
	"84e6479646f33474b385048354645560a782f567a497a5446727044564d4d69345642546f63336541" +
	"5933674b65746c71533669686d73456c677861643048316943345a356e343145756c5049464868440" +
	"a466657575341764e6656693868582b75546f47335452584f70446932503750384b6c4a756d556750" +
	"676f5331415544466a6530735971343635356a394d51724d0a4d49656e734e586971734f64536d6a3" +
	"761336d61516345436759454167367a3769734d567063664b634478586e544873633132705a52466a" +
	"34632f53553455320a3373326c504d77576f344c49513134536a504b7757522f37706341556637774" +
	"65a396d696e4d59386c4c462f72394e4f43472b3479727741374f3431454d504f0a4174546d39326b" +
	"4d686234534e45434d6a6c6d30685756764e3662315159767561707a335141374344454f385a612b7" +
	"5456561376c727545784b5874454979310a51355a4e2b4d4d436759413364774a4755735832574472" +
	"59784d4a395842744750484f576e6862624b5a68716a696c75444c673731696a61557570375058704" +
	"20a754e7048424b6e387832384e49784c2f5248385a30654462345553784c685a556a37613978434d" +
	"4a632b757364636c386e4f663370413769716b4f6d714e4e5a0a51456c4b452f7752395a6b6e6b384" +
	"145726f7167322f686a53516c2b433458343736735438624f4145337352506948474e6c476354673d" +
	"3d0a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a"

var publicKeyMemHex = "2d2d2d2d2d424547494e20525341205055424c4943204b45592d2d2d2d2d0a4" +
	"d49494243674b434151454173697367323179636c746f626c48506847744c624a713850356a434d63" +
	"2f546b3248305736582b7757656b312f7478574c6448790a594c5847533651784f5439574e7457784" +
	"77a2b5351667443646e44736238637159555669785544682f484d666c5476726f3537585141376570" +
	"456b6f567050730a5370304e554e66327a44742f58344a47646a454f69516d53587136476b4352763" +
	"7347273394f64537457673977597135376955456147466b47573644435a4f350a4833507352576543" +
	"5961554e55666d3652463668634d593364614e674c7867557053576a7368334b514264496c6650517" +
	"04f37314b77426839526b5743425a490a45423169565733314c6b4d7771725a50454e4b653053414b" +
	"715075414f75506345306f6656674f36692b315a696662384e774569566e6f56386375526f657a650" +
	"a757a3367365677457a5746532b43585a586176746961644b452f53396f5968454577494441514142" +
	"0a2d2d2d2d2d454e4420525341205055424c4943204b45592d2d2d2d2d0a"

var msg = "I am a secret message: Never gonna give you up!"

func TestCreate(t *testing.T) {
	var r RSA
	priv, pub := r.Create()

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
	var r RSA = RSA{
		AsymmetricOpt: helper.AsymmetricOpt{
			KeyTypes: "TEST",
		},
	}
	if r.GetAlg() != "TEST" {
		t.Errorf("Alg is not matching: expected: %s, actual: %s", "TEST", r.GetAlg())
		return
	}
	t.Logf("AlgTest was successful expected: %s, actual: %s", "TEST", r.GetAlg())
}

func TestGetInfo(t *testing.T) {
	var asymOpt helper.AsymmetricOpt = helper.AsymmetricOpt{
		Name:        "TEST1",
		Version:     100,
		WriteToFile: false,
		Hash:        "SHA1",
		KeyTypes:    "TEST2",
	}
	var r RSA = RSA{
		AsymmetricOpt: asymOpt,
	}
	if r.AsymmetricOpt != asymOpt {
		t.Errorf("AsymmetricOpt are not matching: expected: %v, actual: %v", asymOpt, r.AsymmetricOpt)
		return
	}
	t.Logf("AsymmetricOptTest was successful expected: %v, actual: %v", asymOpt, r.AsymmetricOpt)
}

func TestKeysMem(t *testing.T) {
	var privateKey rsa.PrivateKey = *MemToPrivateKey(helper.FromHex(privateKeyMemHex))
	var publicKey rsa.PublicKey = *MemToPublicKey(helper.FromHex(publicKeyMemHex))
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
		KeyAlg:     "RSASSA_PKCS1_V1_5",
		KeySize:    1024,
		KeyUse:     "ENC",
		PrivateKey: privateKeyMemHex,
		PublicKey:  publicKeyMemHex,
	}
	var r RSA
	r.Bind(key)
	if r.KeySize != 1024 ||
		helper.ToHex(PrivateKeyToMem(&r.PrivateKey)) != privateKeyMemHex ||
		helper.ToHex(PublicKeyToMem(&r.PublicKey)) != publicKeyMemHex ||
		r.AsymmetricOpt.Name != key.KeyName ||
		r.AsymmetricOpt.KeyTypes != string(helper.RSAKeyTypes(key.KeyAlg)) ||
		r.AsymmetricOpt.Version != key.KeyVersion ||
		r.AsymmetricOpt.Hash != helper.Hashes(helper.UNKNOWN) {
		t.Errorf("Bind was not successful. RSA: %v, Used Key: %v", r, key)
	}
}
func TestEncryptDecrypt(t *testing.T) {
	var r RSA
	r.PublicKey = *MemToPublicKey(helper.FromHex(publicKeyMemHex))
	var encmsg string = r.Encrypt(helper.ToHex([]byte(msg)))

	r.PrivateKey = *MemToPrivateKey(helper.FromHex(privateKeyMemHex))
	var msg2 string = string(helper.FromHex(r.Decrypt(encmsg)))

	if msg2 != msg {
		t.Errorf("Expected %s, Actual %s", msg, msg2)
	}
}
