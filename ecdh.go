package ecdh

import (
	"io"
)

// The main interface for ECDH key exchange.
type ECDH interface {
	GenerateKey(io.Reader) (*EllipticPrivateKey, *EllipticPublicKey, error)
	Marshal(priKey *EllipticPublicKey) ([]byte, error)
	Unmarshal([]byte) (*EllipticPublicKey, error)
	// X509MarshalPublicKey(p crypto.PublicKey) ([]byte, error)
	// X509UnmarshalPublicKey(data []byte) (crypto.PublicKey, error)
	GenerateSharedSecret(*EllipticPrivateKey, *EllipticPublicKey) ([]byte, error)
}
