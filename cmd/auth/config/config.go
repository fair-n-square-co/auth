package config

import (
	"embed"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/fair-n-square-co/auth/internal/auth/db"
	"github.com/fair-n-square-co/auth/internal/oidc/workos"
	"github.com/fair-n-square-co/auth/pkg/logger"
	"github.com/spf13/viper"
)

//go:embed *.yml
var configFiles embed.FS

// Config is the fully-resolved application configuration. Sub-configs are
// composed from the packages that own them (e.g. db.DBConfig, workos.Config) so
// each module defines its own settings and they are populated here in one place.
type Config struct {
	Port   int
	TLS    TLSConfig
	HTTP   HTTPConfig
	Logger logger.LogConfig
	Db     db.DBConfig
	Workos workos.Config

	viperReader *viper.Viper
}

// HTTPConfig holds the server's connection timeouts. ReadHeaderTimeout bounds
// how long the server waits for request headers; IdleTimeout bounds idle
// keep-alive connections between requests. ReadTimeout/WriteTimeout are omitted
// so long-lived streaming RPCs are not cut off.
type HTTPConfig struct {
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
}

// TLSConfig configures optional TLS termination for the server. When both
// CertFile and KeyFile are set the server serves HTTPS and negotiates HTTP/2 via
// ALPN; otherwise it serves cleartext HTTP/1.1 + h2c for local development. The
// cert/key paths come from the AUTH_TLS_* env vars, not the checked-in YAML.
type TLSConfig struct {
	CertFile string
	KeyFile  string
}

// Enabled reports whether TLS is configured (both a cert and a key are set).
func (t TLSConfig) Enabled() bool {
	return t.CertFile != "" && t.KeyFile != ""
}

// LoadConfig resolves config in two passes into the same struct: embedded YAML
// first, then environment variables (prefixed AUTH_) which override the YAML.
// Defaults live solely in the embedded YAML (config.yml / config.prod.yml) so
// they are not duplicated in Go.
func LoadConfig() (*Config, error) {
	config := &Config{}

	if err := config.readViperConfig("yaml"); err != nil {
		return nil, fmt.Errorf("config error: failed to read yaml config: %w", err)
	}
	if err := config.readViperConfig("env"); err != nil {
		return nil, fmt.Errorf("config error: failed to read env config: %w", err)
	}

	return config, nil
}

// readViperConfig runs a single resolution pass and unmarshals into the shared
// Config. ExperimentalBindStruct lets AutomaticEnv bind to struct fields without
// explicit BindEnv calls; KeyDelimiter("_") makes nested keys map to env vars
// like AUTH_DB_CONNSTRING.
func (c *Config) readViperConfig(configType string) error {
	c.viperReader = viper.NewWithOptions(
		viper.ExperimentalBindStruct(),
		viper.KeyDelimiter("_"),
	)

	if configType == "env" {
		c.viperReader.SetConfigType("env")
		c.viperReader.SetEnvPrefix("auth")
		c.viperReader.AutomaticEnv()
	} else {
		configFile, err := getConfigFile()
		if err != nil {
			return fmt.Errorf("failed to get config file: %w", err)
		}
		c.viperReader.SetConfigType("yaml")
		if err := c.viperReader.ReadConfig(strings.NewReader(configFile)); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				slog.Info("config file not found, using defaults", slog.String("configType", configType))
				return nil
			}
			return fmt.Errorf("failed to read config: %w", err)
		}
	}

	if err := c.viperReader.Unmarshal(c); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

// getConfigFile returns the embedded YAML for the current ENV ("production"
// selects config.prod.yml; everything else uses config.yml).
func getConfigFile() (string, error) {
	name := "config.yml"
	if os.Getenv("AUTH_ENV") == "production" {
		name = "config.prod.yml"
	}
	b, err := configFiles.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("read embedded %s: %w", name, err)
	}
	return string(b), nil
}
