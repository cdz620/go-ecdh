package ecdh

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"github.com/stretchr/testify/require"
)

func TestNIST224(t *testing.T) {
	testECDH(NewEllipticECDH(elliptic.P224()), t)
	testEllipticECDH(NewEllipticECDH(elliptic.P224()), t)
}

func TestNIST256(t *testing.T) {
	testECDH(NewEllipticECDH(elliptic.P256()), t)
	testEllipticECDH(NewEllipticECDH(elliptic.P256()), t)
}

func TestNIST384(t *testing.T) {
	testECDH(NewEllipticECDH(elliptic.P384()), t)
	testEllipticECDH(NewEllipticECDH(elliptic.P384()), t)
}

func TestNIST521(t *testing.T) {
	testECDH(NewEllipticECDH(elliptic.P521()), t)
	testEllipticECDH(NewEllipticECDH(elliptic.P521()), t)
}

func BenchmarkNIST224(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testECDH(NewEllipticECDH(elliptic.P224()), b)
	}
}

func BenchmarkNIST256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testECDH(NewEllipticECDH(elliptic.P256()), b)
	}
}

func BenchmarkNIST384(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testECDH(NewEllipticECDH(elliptic.P384()), b)
	}
}

func BenchmarkNIST521(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testECDH(NewEllipticECDH(elliptic.P521()), b)
	}
}

func testECDH(e ECDH, t testing.TB) {
	var privKey1, privKey2 *EllipticPrivateKey
	var pubKey1, pubKey2 *EllipticPublicKey
	var pubKey1Buf, pubKey2Buf []byte
	var err error
	var secret1, secret2 []byte

	privKey1, pubKey1, err = e.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	privKey2, pubKey2, err = e.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}

	// test marshal & unmarshal
	pubKey1Buf, _ = e.Marshal(pubKey1)
	pubKey2Buf, _ = e.Marshal(pubKey2)

	pubKey1, err = e.Unmarshal(pubKey1Buf)
	if err != nil {
		t.Fatalf("Unmarshal does not work")
	}

	pubKey2, err = e.Unmarshal(pubKey2Buf)
	if err != nil {
		t.Fatalf("Unmarshal does not work")
	}

	// test generate share secret
	secret1, err = e.GenerateSharedSecret(privKey1, pubKey2)
	if err != nil {
		t.Error(err)
	}
	secret2, err = e.GenerateSharedSecret(privKey2, pubKey1)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(secret1, secret2) {
		t.Fatalf("The two shared keys: %d, %d do not match", secret1, secret2)
	}
}

func testEllipticECDH(e ECDH, t testing.TB) {
	r := require.New(t)
	ec, ok := e.(*EllipticECDH)
	r.Equal(true, ok)

	var privKey1, privKey2 *EllipticPrivateKey
	var pubKey1, pubKey2 *EllipticPublicKey
	var pubKey1Buf, pubKey2Buf []byte
	var err error
	var secret1, secret2 []byte
	// test x509 suit
	privKey1, pubKey1, err = ec.GenerateKey(rand.Reader)
	r.NoError(err)
	privKey2, pubKey2, err = ec.GenerateKey(rand.Reader)
	r.NoError(err)

	// test marshal & unmarshal
	pubKey1Buf, err = ec.X509MarshalPublicKey(pubKey1)
	r.NoError(err)
	pubKey2Buf, err = ec.X509MarshalPublicKey(pubKey2)
	r.NoError(err)

	pubKey1, err = ec.X509UnmarshalPublicKey(pubKey1Buf)
	r.NoError(err)

	pubKey2, err = ec.X509UnmarshalPublicKey(pubKey2Buf)
	r.NoError(err)

	// test generate share secret
	secret1, err = ec.GenerateSharedSecret(privKey1, pubKey2)
	r.NoError(err)
	secret2, err = ec.GenerateSharedSecret(privKey2, pubKey1)
	r.NoError(err)
	r.Equal(secret1, secret2)
}

func TestEcParameterExplicit(t *testing.T) {
	// assert
	r := require.New(t)
	var clientPub = []byte(`-----BEGIN PUBLIC KEY-----
MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAA
AAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA////
///////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSd
NgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5
RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA
//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABPNJMBeUr2o3klNJ61d18CVu
D9eDkTAErOu2HYrdkjYCh4MGeaYRzBe7jsY3TObLznqsG7js2/isyXdsloA2S/A=
-----END PUBLIC KEY-----`)
	ec := NewEllipticECDH(elliptic.P256())
	pub, err := ec.X509UnmarshalPublicKey(clientPub)
	r.NoError(err)
	r.NotEqual(nil, pub.X)

	pem, err := ec.X509MarshalPublicKey(pub)
	r.NoError(err)
	r.True(len(pem) > 0)
	// fmt.Println(string(pem))
}
