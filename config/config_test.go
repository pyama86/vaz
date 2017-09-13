package config

import "testing"

func TestNewConfig(t *testing.T) {
	c, err := NewConfig("../config/test.toml")
	if err != nil {
		t.Fatalf("Config load failed")
	}

	if c.Service != "example" {
		t.Errorf("Config cannot parse Service")
	}

	if c.Token != "token" {
		t.Errorf("Config cannot parse Token")
	}
}

func TestNewConfigError(t *testing.T) {
	_, err := NewConfig("../config/test-absent.toml")
	if err == nil {
		t.Errorf("Config cannot handle errors")
	}
}
