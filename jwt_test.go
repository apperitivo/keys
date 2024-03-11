package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	p, err := rsa.GenerateKey(rand.New(rand.NewSource(time.Now().Unix())), 2048)
	assert.Nilf(t, err, "should not fail to generate a key")
	privKeyBytes := x509.MarshalPKCS1PrivateKey(p)
	
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&p.PublicKey)
	assert.Nilf(t, err, "should not fail to marshal public key")

	privPem := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	pubPem := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	encodedPriv := base64.RawStdEncoding.EncodeToString(pem.EncodeToMemory(&privPem))
	encodedPub := base64.RawStdEncoding.EncodeToString(pem.EncodeToMemory(&pubPem))

	err = Init([]byte(encodedPriv), []byte(encodedPub))
	assert.Nilf(t, err, "should be able to init")
}
