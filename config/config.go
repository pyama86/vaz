package config

import (
	"errors"

	"github.com/BurntSushi/toml"
)

// Config Config Struct
type Config struct {
	ServerEndpoint string `toml:"-"`
	Service        string `toml:"service"`
	Token          string `toml:"token"`
}

// NewConfig Config initialize
func NewConfig(confPath string) (*Config, error) {
	var conf Config
	defaultConfig(&conf)

	if _, err := toml.DecodeFile(confPath, &conf); err != nil {
		return nil, err
	}

	if conf.Service == "" {
		return nil, errors.New("Service name(service) is required")
	}
	return &conf, nil
}

func defaultConfig(c *Config) {
	c.ServerEndpoint = "https://veeta.org/api/v1/hosts"
}
