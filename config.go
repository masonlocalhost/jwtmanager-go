package jwtmanager

import "time"

type JWTConfig struct {
	PrivateKey PrivateKey `mapstructure:"privateKey"`
	PublicKey  PublicKey  `mapstructure:"publicKey"`

	AccessTokenDuration       time.Duration `mapstructure:"accessTokenDuration"`
	RefreshTokenDuration      time.Duration `mapstructure:"refreshTokenDuration"`
	AdminAccessTokenDuration  time.Duration `mapstructure:"adminAccessTokenDuration"`
	AdminRefreshTokenDuration time.Duration `mapstructure:"adminRefreshTokenDuration"`
}

type PrivateKey struct {
	File string `mapstructure:"file"`
}

type PublicKey struct {
	File string `mapstructure:"file"`
}
