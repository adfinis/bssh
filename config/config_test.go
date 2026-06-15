package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func baseConfig() *Config {
	return &Config{
		Username:   "user",
		Hostname:   "bastion.example.com",
		Port:       22,
		SSHCommand: "ssh -t",
	}
}

func TestValidateConfig_MinimalValid(t *testing.T) {
	assert.NoError(t, validateConfig(baseConfig()))
}

func TestValidateConfig_OTPDisabledIgnoresOTPFields(t *testing.T) {
	c := baseConfig()
	// OTP fields may be empty when OTP is not enabled.
	assert.NoError(t, validateConfig(c))
}

func TestValidateConfig_OTPEnabledRequiresCallback(t *testing.T) {
	c := baseConfig()
	c.OTPEnabled = true
	c.OTPShellCommand = "/usr/bin/env bash -c"
	err := validateConfig(c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "otp_callback_command")
}

func TestValidateConfig_OTPEnabledValid(t *testing.T) {
	c := baseConfig()
	c.OTPEnabled = true
	c.OTPShellCommand = "/usr/bin/env bash -c"
	c.OTPCallbackCommand = "echo 123456"
	assert.NoError(t, validateConfig(c))
}

func TestValidateConfig_OpenBaoEnabledRequiresFields(t *testing.T) {
	c := baseConfig()
	c.OpenBao.Enabled = true
	c.OpenBao.MountPath = "ssh"

	err := validateConfig(c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "openbao.address")

	c.OpenBao.Address = "https://bao.example.com:8200"
	err = validateConfig(c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "openbao.role")

	c.OpenBao.Role = "bastion"
	err = validateConfig(c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "openbao.public_key")

	c.OpenBao.PublicKey = "~/.ssh/id_ed25519.pub"
	assert.NoError(t, validateConfig(c))
}

func TestValidateConfig_OpenBaoDisabledIgnoresFields(t *testing.T) {
	c := baseConfig()
	// OpenBao fields may be empty when the feature is disabled.
	assert.NoError(t, validateConfig(c))
}
