package config

import "testing"

func TestNewConfig(t *testing.T) {
	c, err := NewConfig("../vaz/test.toml")
	if err != nil {
		t.Fatalf("Config load failed")
	}

	if c.ServerEndpoint != "https://localhost/test" {
		t.Errorf("Config cannot parse ServerEndpoint")
	}

	if c.SslVerify != false {
		t.Errorf("Config cannot parse SslVerify")
	}

	if c.ScanInterval != 4000 {
		t.Errorf("Config cannot parse ScanInterval")
	}
}

func TestNewConfigError(t *testing.T) {
	_, err := NewConfig("../config/test-absent.toml")
	if err == nil {
		t.Errorf("Config cannot handle errors")
	}
}
