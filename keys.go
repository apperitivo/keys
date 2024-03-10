package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/rand"
	"time"
)

func NewRsaKeyPemBytes() ([]byte, []byte, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	key, err := rsa.GenerateKey(r, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Encode private key to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	privateKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key to PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	publicKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKeyPem, publicKeyPem, nil
}
