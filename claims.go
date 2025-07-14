package jwtmanager

import "github.com/golang-jwt/jwt/v5"

// Identity
type Identity struct {
	Metadata  map[string]string `json:"metadata"`
	ID        string            `json:"id"`
	SessionID string            `json:"sid"`
	Domain    string            `json:"dom"`
	DeviceID  string            `json:"did"`
	Roles     []string          `json:"roles"`
}

type Claims struct {
	Identity
	jwt.RegisteredClaims
}
