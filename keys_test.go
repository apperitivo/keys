package keys

import "testing"

func TestNewRsaKeyPemBytes(t *testing.T) {
	privateKeyPem, publicKeyPem, err := NewRsaKeyPemBytes()
	if err != nil {
		t.Fatal(err)
	}
	if privateKeyPem == nil {
		t.Fatal("privateKeyPem is nil")
	}
	if publicKeyPem == nil {
		t.Fatal("publicKeyPem is nil")
	}
}
