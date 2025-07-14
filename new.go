package jwtmanager

import (
	"crypto"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Service struct {
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey

	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
	issuer               string
}

func NewService(config *JWTConfig) (*Service, error) {
	service := &Service{
		accessTokenDuration:  config.AccessTokenDuration,
		refreshTokenDuration: config.RefreshTokenDuration,
		issuer:               "app",
	}
	privateKey, err := LoadPrivateKey(config.PrivateKey.File)
	if err != nil {
		return nil, fmt.Errorf("cannot load private key: %v", err)
	}
	service.privateKey = privateKey

	publicKey, err := LoadPublicKey(config.PublicKey.File)
	if err != nil {
		return nil, fmt.Errorf("cannot load public key: %v", err)
	}
	service.publicKey = publicKey

	return service, nil
}

func (jm *Service) Verify(accessToken string) (*Identity, int64, error) {
	var claims = &Claims{}

	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (any, error) {
		return jm.publicKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, 0, fmt.Errorf("invalid signature: %v", err)
		}

		return nil, 0, err
	}

	if !token.Valid {
		return nil, 0, fmt.Errorf("invalid token: %v", err)
	}

	return &claims.Identity, int64(claims.ExpiresAt.Unix()), nil
}

func (jm *Service) GenerateAccessToken(id, tokenID, role string) (string, error) {
	return jm.Generate(id, tokenID, role, jm.accessTokenDuration)
}

func (jm *Service) GenerateRefreshToken(id, tokenID, role string) (string, error) {
	return jm.Generate(id, tokenID, role, jm.refreshTokenDuration)
}

func (jm *Service) Generate(id, tokenID, role string, duration time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		Identity: Identity{
			ID:    id,
			Roles: []string{role},
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    jm.issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(jm.privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, err
}
