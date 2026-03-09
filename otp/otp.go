package otp

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	bastion "github.com/adfinis/bastion-go"
	"github.com/adfinis/bssh/config"
)

// NewCallback returns a function that executes the configured OTP shell command
// and returns the resulting code.
func NewCallback(cfg *config.Config) func() (string, error) {
	return func() (string, error) {
		shellParts := strings.Fields(cfg.OTPShellCommand)
		shellParts = append(shellParts, cfg.OTPCallbackCommand)
		cmd := exec.Command(shellParts[0], shellParts[1:]...)
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("failed to get OTP: %w", err)
		}
		outStr := strings.TrimSpace(string(out))
		if _, err := strconv.Atoi(outStr); err != nil {
			return "", fmt.Errorf("OTP command output is not a valid number: %s", outStr)
		}
		return outStr, nil
	}
}

// WithAuth returns a bastion-go SSHAuthMethod that handles keyboard-interactive
// challenges by answering with OTP codes obtained from the configured command.
func WithAuth(cfg *config.Config) bastion.SSHAuthMethod {
	callback := NewCallback(cfg)
	return bastion.WithKeyboardInteractiveAuth(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range questions {
			code, err := callback()
			if err != nil {
				return nil, err
			}
			answers[i] = code
		}
		return answers, nil
	})
}
