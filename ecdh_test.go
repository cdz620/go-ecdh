package ecdh

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"github.com/stretchr/testify/require"
	"encoding/pem"
	"crypto/x509"
	"crypto/ecdsa"
	"fmt"
	"reflect"
	"encoding/base64"
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

func TestEcc(t *testing.T) {
	// assert
	r := require.New(t)
	cliPubBytes := []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJr/X/vpUoAlJ5RBMW9m4bI13RkXI
Jx5CUsYPk+JC1EANHkeH5lpEeY1uxIJ8WEDyfgy6YVfPJri93X9KEQixng==
-----END PUBLIC KEY-----`)
	serPriBytes := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII7BB2KdPVOppd5X8O2tB6MSNoSk25PX2fvSOmHkP2fUoAoGCCqGSM49
AwEHoUQDQgAEdDndAOfQ8aYEK7JECZ0+a0J9aWHjS9FyV+i68qE4zCOdGWN6Q7td
zjPkK5LvNusUCFbv6nLKlk1j8t2Hrc+3lw==
-----END EC PRIVATE KEY-----`)

	block, _ := pem.Decode(serPriBytes)
	r.NotEqual(nil, block)
	serPriKey, err := x509.ParseECPrivateKey(block.Bytes)
	r.NoError(err)

	block, _ = pem.Decode(cliPubBytes)
	r.NotEqual(nil, block)

	tp, err := x509.ParsePKIXPublicKey(block.Bytes)
	r.NoError(err)
	cliPubkey := tp.(*ecdsa.PublicKey)

	// x1, y1 := cliPubkey.Curve.ScalarBaseMult(serPriKey.D.Bytes())
	shareKey, _ := serPriKey.Curve.ScalarMult(cliPubkey.X, cliPubkey.Y, serPriKey.D.Bytes())

	// fmt.Println(string(base64.StdEncoding.EncodeToString(x1.Bytes())), "\t", string(base64.StdEncoding.EncodeToString(y1.Bytes())))
	fmt.Println(string(base64.StdEncoding.EncodeToString(shareKey.Bytes())))

}

func encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
}

func decode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey
}

func TestEncodeDecode(t *testing.T) {

	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey := &privateKey.PublicKey

	encPriv, encPub := encode(privateKey, publicKey)

	fmt.Println(encPriv)
	fmt.Println(encPub)

	priv2, pub2 := decode(encPriv, encPub)

	if !reflect.DeepEqual(privateKey, priv2) {
		fmt.Println("Private keys do not match.")
	}
	if !reflect.DeepEqual(publicKey, pub2) {
		fmt.Println("Public keys do not match.")
	}
}

// https://github.com/golang/go/issues/26020
func TestUnexpectedScalarMultResult(t *testing.T) {
	// assert
	r := require.New(t)
	expectedSharedKey := "ACjIKHvl1FAT1zAEQ882cmRQjT75GoLk6MpGHsiDqno="

	var cliPubBytes = []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJr/X/vpUoAlJ5RBMW9m4bI13RkXI
Jx5CUsYPk+JC1EANHkeH5lpEeY1uxIJ8WEDyfgy6YVfPJri93X9KEQixng==
-----END PUBLIC KEY-----`)


	var serPriBytes = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII7BB2KdPVOppd5X8O2tB6MSNoSk25PX2fvSOmHkP2fUoAoGCCqGSM49
AwEHoUQDQgAEdDndAOfQ8aYEK7JECZ0+a0J9aWHjS9FyV+i68qE4zCOdGWN6Q7td
zjPkK5LvNusUCFbv6nLKlk1j8t2Hrc+3lw==
-----END EC PRIVATE KEY-----`)


	ec := NewEllipticECDH(elliptic.P256())
	cliPubKey, err := ec.X509UnmarshalPublicKey(cliPubBytes)
	r.NoError(err)

	serPriKey, err := ec.X509UnmarshalPrivateKey(serPriBytes)
	r.NoError(err)

	keyBytes, err := ec.GenerateSharedSecret(serPriKey, cliPubKey)
	r.NoError(err)

	sharedKey := base64.StdEncoding.EncodeToString(keyBytes)

	r.Equal(expectedSharedKey, sharedKey)

}
