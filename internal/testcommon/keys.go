package testcommon

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func GenerateHostKey(t *testing.T) string {
	bitSize := 1024

	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		t.Fatalf("Failed to validate key: %v", err)
	}

	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privateKeyBytes := pem.EncodeToMemory(&privBlock)

	keyDir := t.TempDir()
	privateKeyFile := keyDir + "/id_rsa"
	//nolint:gomnd // Ignore for test
	if err := os.WriteFile(privateKeyFile, privateKeyBytes, 0o600); err != nil {
		t.Fatalf("Failed to write key: %v", err)
	}

	return privateKeyFile
}
