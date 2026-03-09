package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/adrg/xdg"
	"github.com/charmbracelet/log"
	"github.com/spf13/viper"
)

type Config struct {
	Username           string `mapstructure:"username"`
	Hostname           string `mapstructure:"hostname"`
	Port               int    `mapstructure:"port"`
	SSHCommand         string `mapstructure:"ssh_command"`
	OTPCallbackCommand string `mapstructure:"otp_callback_command"`
	OTPShellCommand    string `mapstructure:"otp_shell_command"`
}

var v = viper.New()

func GetViper() *viper.Viper {
	return v
}

func init() {
	setDefaults(v)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("BSSH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
}

func Load(path string) (*Config, error) {
	var configFileFound bool
	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(".")
		v.AddConfigPath(filepath.Join(xdg.ConfigHome, "bssh"))
		v.AddConfigPath("/etc/bssh")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	} else {
		configFileFound = true
	}

	if configFileFound {
		log.Debug("Using config file", "file", v.ConfigFileUsed())
	}

	var c Config
	if err := v.Unmarshal(&c); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := validateConfig(&c); err != nil {
		return nil, err
	}

	return &c, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("port", 22)
	v.SetDefault("ssh_command", "ssh -t")
	v.SetDefault("otp_shell_command", "/usr/bin/env bash -c")
}

func validateConfig(c *Config) error {
	if c == nil {
		return fmt.Errorf("missing bssh config")
	}

	if c.Username == "" {
		return fmt.Errorf("username is required in config")
	}

	if c.Hostname == "" {
		return fmt.Errorf("hostname is required in config")
	}

	if c.OTPCallbackCommand == "" {
		return fmt.Errorf("otp_callback_command is required in config")
	}

	if c.OTPShellCommand == "" {
		return fmt.Errorf("otp_shell_command is required in config")
	}

	if c.SSHCommand == "" {
		return fmt.Errorf("ssh_command is required in config")
	}

	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	return nil
}
