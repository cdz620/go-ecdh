package ecdh

import (
	"io"
	"crypto"
)

// The main interface for ECDH key exchange.
type ECDH interface {
	GenerateKey(io.Reader) (crypto.PrivateKey, crypto.PublicKey, error)
	Marshal(crypto.PublicKey) ([]byte, error)
	Unmarshal([]byte) (crypto.PublicKey, error)
	// X509Marshal(p crypto.PublicKey) ([]byte, error)
	// X509Unmarshal(data []byte) (crypto.PublicKey, error)
	GenerateSharedSecret(crypto.PrivateKey, crypto.PublicKey) ([]byte, error)
}
