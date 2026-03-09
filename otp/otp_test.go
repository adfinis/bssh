package otp

import (
	"testing"

	"github.com/adfinis/bssh/config"
	"github.com/stretchr/testify/assert"
)

func TestNewCallback_ValidOTP(t *testing.T) {
	cfg := &config.Config{
		OTPShellCommand:    "/usr/bin/env bash -c",
		OTPCallbackCommand: "echo 123456",
	}
	cb := NewCallback(cfg)
	code, err := cb()
	assert.NoError(t, err)
	assert.Equal(t, "123456", code)
}

func TestNewCallback_NonNumericOutput(t *testing.T) {
	cfg := &config.Config{
		OTPShellCommand:    "/usr/bin/env bash -c",
		OTPCallbackCommand: "echo not-a-number",
	}
	cb := NewCallback(cfg)
	_, err := cb()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid number")
}

func TestNewCallback_CommandFailure(t *testing.T) {
	cfg := &config.Config{
		OTPShellCommand:    "/usr/bin/env bash -c",
		OTPCallbackCommand: "false",
	}
	cb := NewCallback(cfg)
	_, err := cb()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get OTP")
}
