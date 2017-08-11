package config

import "github.com/BurntSushi/toml"

// Config Config Struct
type Config struct {
	ServerEndpoint string `toml:"server_endpoint"`
	SslVerify      bool   `toml:"ssl_verify"`
	ScanInterval   int    `toml:"scan_interval"`
	AccessToken    int    `toml:"access_token"`
}

// NewConfig Config initialize
func NewConfig(confPath string) (Config, error) {
	var conf Config
	defaultConfig(&conf)

	if _, err := toml.DecodeFile(confPath, &conf); err != nil {
		return conf, err
	}
	return conf, nil
}

func defaultConfig(c *Config) {
	c.ServerEndpoint = "https://localhost/v1"
	c.SslVerify = true
	c.ScanInterval = 3600
}
