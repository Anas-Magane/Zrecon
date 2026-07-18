package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	General  GeneralConfig  `mapstructure:"general"`
	Ports    PortsConfig    `mapstructure:"ports"`
	Output   OutputConfig   `mapstructure:"output"`
	Security SecurityConfig `mapstructure:"security"`
}

type GeneralConfig struct {
	Threads   int    `mapstructure:"threads"`
	Timeout   string `mapstructure:"timeout"`
	RateLimit int    `mapstructure:"rate_limit"`
	UserAgent string `mapstructure:"user_agent"`
}

type PortsConfig struct {
	DefaultTopPorts int `mapstructure:"default_top_ports"`
}

type OutputConfig struct {
	Directory string   `mapstructure:"directory"`
	Formats   []string `mapstructure:"formats"`
}

type SecurityConfig struct {
	RequireAuthorization bool `mapstructure:"require_authorization"`
	AllowPrivateTargets  bool `mapstructure:"allow_private_targets"`
}

var defaultConfig = `general:
  threads: 20
  timeout: 10s
  rate_limit: 50
  user_agent: "Zrecon/1.0.0"

ports:
  default_top_ports: 100

output:
  directory: "./results"
  formats:
    - txt
    - json
    - html

security:
  require_authorization: true
  allow_private_targets: false
`

func Load() (*Config, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = os.Getenv("HOME") + "/.config"
	}
	configPath := filepath.Join(configDir, "zrecon")

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configPath)
	viper.AddConfigPath(".")

	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("config read error: %w", err)
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config unmarshal error: %w", err)
	}
	return &cfg, nil
}

func setDefaults() {
	viper.SetDefault("general.threads", 20)
	viper.SetDefault("general.timeout", "10s")
	viper.SetDefault("general.rate_limit", 50)
	viper.SetDefault("general.user_agent", "Zrecon/1.0.0")
	viper.SetDefault("ports.default_top_ports", 100)
	viper.SetDefault("output.directory", "./results")
	viper.SetDefault("output.formats", []string{"txt", "json", "html"})
	viper.SetDefault("security.require_authorization", true)
	viper.SetDefault("security.allow_private_targets", false)
}

func Init() error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = os.Getenv("HOME") + "/.config"
	}
	configPath := filepath.Join(configDir, "zrecon")
	if err := os.MkdirAll(configPath, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	dest := filepath.Join(configPath, "config.yaml")
	if _, err := os.Stat(dest); err == nil {
		fmt.Printf("Config already exists: %s\n", dest)
		return nil
	}
	if err := os.WriteFile(dest, []byte(defaultConfig), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Printf("Config created: %s\n", dest)
	return nil
}
