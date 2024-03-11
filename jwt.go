package keys

import (
	"crypto/rsa"
	"fmt"
	"os"
	"sync"

	"github.com/apperitivo/log"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

var key JwtSigningKey
var m sync.Mutex = sync.Mutex{}
var o sync.Once = sync.Once{}
var l *zap.Logger = log.NewLogger("secure")

func InitFromPath(privPath, pubPath string) error {
	privB, err := os.ReadFile(privPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %v", err)
	}

	pubB, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("failed to read pub key path: %v", err)
	}

	return Init(privB, pubB)
}

func InitDefault() error {
	privkey, pubkey, err := NewRsaKeyPemBytes()
	if err != nil {
		return fmt.Errorf("failed to generate rsa key: %v", err)
	}

	return Init(privkey, pubkey)
}

func Init(privKey []byte, pubKey []byte) error {
	m.Lock()
	defer m.Unlock()

	l.Info("parsing keys", zap.ByteString("priv", privKey), zap.ByteString("pub", pubKey))

	// var decodedKey []byte = make([]byte, len(privKey))
	// var decodedPub []byte = make([]byte, len(pubKey))
	// decodedKey, err := base64.RawStdEncoding.DecodeString(string(privKey))
	// if err != nil {
	// 	return fmt.Errorf("failed to base64 decode private key: %v", err)
	// }

	// decodedPub, err := base64.RawStdEncoding.DecodeString(string(pubKey))
	// if err != nil {
	// 	return fmt.Errorf("failed to base64 decode public key: %v", err)
	// }

	rsaKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKey)
	if err != nil {
		return fmt.Errorf("faild to parse RSA Private key: %v", err)
	}

	rsaPubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKey)
	if err != nil {
		return fmt.Errorf("failed to parse RSA public key: %v", err)
	}

	key = &JwtKey{
		key:    *rsaKey,
		pubKey: *rsaPubKey,
	}

	return nil
}

func GetKey() JwtSigningKey {
	o.Do(func() {
		m.Lock()
		defer m.Unlock()

		if key == nil {
			panic("please initialize secure key before using")
		}
	})

	return key
}

type SecureValue[T any] interface {
	Delete()
	GetValue() T
}

type JwtSigningKey interface {
	Sign(claims jwt.Claims) (string, error)
	Decrypt(token string) (*jwt.Token, error)
}

type JwtKey struct {
	key    rsa.PrivateKey
	pubKey rsa.PublicKey
}

func (k *JwtKey) Sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(&k.key)
}

func (k *JwtKey) Decrypt(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("invalid signing method: %v", t.Method)
		}

		return &k.pubKey, nil
	})
}
