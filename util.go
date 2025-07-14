package jwtmanager

import (
	"crypto"
	"os"

	"github.com/golang-jwt/jwt"
)

func LoadPrivateKey(keyFile string) (crypto.PrivateKey, error) {
	bs, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	return jwt.ParseEdPrivateKeyFromPEM(bs)
}

func LoadPublicKey(keyFile string) (crypto.PublicKey, error) {
	bs, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	return jwt.ParseEdPublicKeyFromPEM(bs)
}
