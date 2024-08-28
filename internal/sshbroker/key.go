package sshbroker

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/crypto/ssh"
)

const (
	hostKeySize = 4096
)

func getHostKey(sshHostKeyFile string) (ssh.Signer, error) {
	if sshHostKeyFile != "" {
		privateBytes, err := os.ReadFile(sshHostKeyFile)
		if err != nil {
			slog.Error("getHostKey Failed to load host key", "SshHostKeyFile", sshHostKeyFile, "err", err)

			return nil, fmt.Errorf("failed to load host key: %w", err)
		}

		private, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			slog.Error("Failed to parse private host key", "SshHostKeyFile", sshHostKeyFile, "err", err)

			return nil, fmt.Errorf("failed to parse host key: %w", err)
		}

		return private, nil
	}

	// Should only be using for testing the helm chart
	// i.e. production should always deploy with externally
	// defined host key
	slog.Warn("Using self generated host key")

	privateKey, err := rsa.GenerateKey(rand.Reader, hostKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, fmt.Errorf("failed to validate key: %w", err)
	}

	return ssh.NewSignerFromKey(privateKey) //nolint:wrapcheck // Error will be wrapped by calling code
}
