package config

import (
	"embed"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/fair-n-square-co/auth/internal/auth/db"
	"github.com/fair-n-square-co/auth/pkg/logger"
	"github.com/spf13/viper"
)

//go:embed *.yml
var configFiles embed.FS

// Config is the fully-resolved application configuration. Sub-configs are
// composed from the packages that own them (e.g. db.DBConfig) so each module
// defines its own settings and they are populated here in one place.
//
// TODO(impl): add an OIDC sub-config (issuer, client id, JWKS URL) once the
// WorkOS provider is wired in (see internal/oidc). For FNS-92 the resolver
// trusts BFF-verified claims, so no OIDC settings are required yet.
type Config struct {
	Port   int
	Logger logger.LogConfig
	Db     db.DBConfig

	viperReader *viper.Viper
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
