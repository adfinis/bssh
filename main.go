package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/adfinis/bssh/config"
	"github.com/adfinis/bssh/openbao"
	"github.com/adfinis/bssh/otp"
	"github.com/charmbracelet/fang"
	"github.com/charmbracelet/log"
	"github.com/creack/pty"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

var (
	// Version is the current version of bssh.
	Version = "devel"
	// Commit is the git commit hash of the current version.
	Commit = "none"
)

var exitCode int

var rootCmdFlags struct {
	configPath string
	logLevel   string
}

var rootCmd = &cobra.Command{
	Use:                "bssh [flags] [host] [-- extra-ssh-args...]",
	Short:              "SSH for The Bastion with fancy autocompletion and OTP callback support",
	Args:               cobra.ArbitraryArgs,
	FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
	ValidArgsFunction:  completeHosts,
	CompletionOptions: cobra.CompletionOptions{
		HiddenDefaultCmd: true,
	},
	PersistentPreRun: func(_ *cobra.Command, _ []string) {
		level, err := log.ParseLevel(rootCmdFlags.logLevel)
		if err != nil {
			log.Fatal("Invalid log level", "error", err)
		}
		log.SetLevel(level)
	},
	Run: root,
}

func mustBindPFlag(v *viper.Viper, name string, flag *pflag.Flag) {
	if err := v.BindPFlag(name, flag); err != nil {
		log.Fatal("Failed to bind flag", "name", name, "error", err)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&rootCmdFlags.configPath, "config", "c", "", "Path to config file")
	rootCmd.Flags().StringVar(&rootCmdFlags.logLevel, "log-level", "info", "Log level (debug, info, warn, error, fatal)")

	rootCmd.Flags().String("username", "", "SSH username")
	rootCmd.Flags().String("hostname", "", "SSH hostname")
	rootCmd.Flags().Int("port", 0, "SSH port")
	rootCmd.Flags().String("ssh-command", "", "SSH command (default \"ssh -t\")")
	rootCmd.Flags().Bool("otp-enabled", false, "Enable OTP callback")
	rootCmd.Flags().String("otp-callback-command", "", "Command to obtain OTP code")
	rootCmd.Flags().String("otp-shell-command", "", "Shell command to run OTP callback (default \"/usr/bin/env bash -c\")")
	rootCmd.Flags().Bool("openbao-enabled", false, "Sign an SSH key with the OpenBao SSH engine and use the certificate to log in")
	rootCmd.Flags().String("openbao-address", "", "OpenBao server address (URL)")
	rootCmd.Flags().String("openbao-mount-path", "", "OpenBao SSH engine mount path (default \"ssh\")")
	rootCmd.Flags().String("openbao-role", "", "OpenBao SSH engine role used to sign the key")
	rootCmd.Flags().String("openbao-public-key", "", "Path to the SSH public key to sign")
	rootCmd.Flags().String("openbao-private-key", "", "Path to the matching SSH private key (default: public key without .pub)")
	rootCmd.Flags().String("openbao-cert-output", "", "Path to write the signed certificate (default: temporary file)")
	rootCmd.Flags().String("openbao-ttl", "5m", "TTL for OpenBao-signed certificates (default 5m)")

	v := config.GetViper()
	mustBindPFlag(v, "username", rootCmd.Flags().Lookup("username"))
	mustBindPFlag(v, "hostname", rootCmd.Flags().Lookup("hostname"))
	mustBindPFlag(v, "port", rootCmd.Flags().Lookup("port"))
	mustBindPFlag(v, "ssh_command", rootCmd.Flags().Lookup("ssh-command"))
	mustBindPFlag(v, "otp_enabled", rootCmd.Flags().Lookup("otp-enabled"))
	mustBindPFlag(v, "otp_callback_command", rootCmd.Flags().Lookup("otp-callback-command"))
	mustBindPFlag(v, "otp_shell_command", rootCmd.Flags().Lookup("otp-shell-command"))
	mustBindPFlag(v, "openbao.enabled", rootCmd.Flags().Lookup("openbao-enabled"))
	mustBindPFlag(v, "openbao.address", rootCmd.Flags().Lookup("openbao-address"))
	mustBindPFlag(v, "openbao.mount_path", rootCmd.Flags().Lookup("openbao-mount-path"))
	mustBindPFlag(v, "openbao.role", rootCmd.Flags().Lookup("openbao-role"))
	mustBindPFlag(v, "openbao.public_key", rootCmd.Flags().Lookup("openbao-public-key"))
	mustBindPFlag(v, "openbao.private_key", rootCmd.Flags().Lookup("openbao-private-key"))
	mustBindPFlag(v, "openbao.cert_output", rootCmd.Flags().Lookup("openbao-cert-output"))
	mustBindPFlag(v, "openbao.ttl", rootCmd.Flags().Lookup("openbao-ttl"))
}

func main() {
	if err := fang.Execute(
		context.Background(),
		rootCmd,
		fang.WithCommit(Commit),
		fang.WithVersion(Version),
	); err != nil {
		os.Exit(1)
	}
}

func extractUnknownArgs(flags *pflag.FlagSet, args []string) []string {
	var unknownArgs []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		var f *pflag.Flag
		if a[0] == '-' {
			if a[1] == '-' {
				f = flags.Lookup(strings.SplitN(a[2:], "=", 2)[0])
			} else {
				for _, s := range a[1:] {
					f = flags.ShorthandLookup(string(s))
					if f == nil {
						break
					}
				}
			}
		}
		if f != nil {
			if f.NoOptDefVal == "" && i+1 < len(args) && f.Value.String() == args[i+1] {
				i++
			}
			continue
		}
		unknownArgs = append(unknownArgs, a)
	}
	return unknownArgs
}

func root(cmd *cobra.Command, _ []string) {
	unknownArgs := extractUnknownArgs(cmd.Flags(), os.Args[1:])
	log.Debug("Unknown args", "args", unknownArgs)

	log.Debug("Loading config", "path", rootCmdFlags.configPath)
	cfg, err := config.Load(rootCmdFlags.configPath)
	if err != nil {
		log.Fatal("Failed to load config", "error", err)
	}
	log.Debug("Config loaded",
		"username", cfg.Username,
		"hostname", cfg.Hostname,
		"port", cfg.Port,
		"ssh_command", cfg.SSHCommand,
		"otp_enabled", cfg.OTPEnabled,
		"otp_shell_command", cfg.OTPShellCommand,
		"otp_callback_command", cfg.OTPCallbackCommand,
		"openbao_enabled", cfg.OpenBao.Enabled,
	)

	sshParts := strings.Fields(cfg.SSHCommand)

	if cfg.OpenBao.Enabled {
		log.Debug("Signing SSH key with OpenBao",
			"address", cfg.OpenBao.Address,
			"mount_path", cfg.OpenBao.MountPath,
			"role", cfg.OpenBao.Role,
			"public_key", cfg.OpenBao.PublicKey,
		)
		signed, err := openbao.Sign(cfg)
		if err != nil {
			log.Fatal("Failed to sign SSH key with OpenBao", "error", err)
		}
		certPath, cleanup, err := signed.Write(cfg)
		if err != nil {
			log.Fatal("Failed to write signed certificate", "error", err)
		}
		defer cleanup()
		log.Debug("SSH key signed", "certificate", certPath, "identity", signed.PrivateKey)
		sshParts = append(sshParts,
			"-o", "CertificateFile="+certPath,
			"-o", "IdentityFile="+signed.PrivateKey,
			"-o", "IdentitiesOnly=yes",
		)
	}

	sshParts = append(sshParts, fmt.Sprintf("%s@%s", cfg.Username, cfg.Hostname), "--")
	sshParts = append(sshParts, unknownArgs...)
	log.Debug("SSH command", "parts", sshParts)

	sshCmd := exec.Command(sshParts[0], sshParts[1:]...)

	ptmx, err := pty.Start(sshCmd)
	if err != nil {
		log.Fatal("Failed to start SSH", "error", err)
	}
	defer ptmx.Close() //nolint:errcheck

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for range sigCh {
			_ = pty.InheritSize(os.Stdin, ptmx)
		}
	}()
	sigCh <- syscall.SIGWINCH

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal("Failed to set terminal to raw mode", "error", err)
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()

	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()

	handleOutput(ptmx, cfg)

	if err := sshCmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	log.Debug("SSH exited", "code", exitCode)
}

func handleOutput(ptmx *os.File, cfg *config.Config) {
	buf := make([]byte, 4096)
	var acc bytes.Buffer
	// When OTP is disabled, treat it as already handled so the prompt is never
	// watched for and no callback is invoked.
	otpDone := !cfg.OTPEnabled
	deadline := time.Now().Add(10 * time.Second)
	callback := otp.NewCallback(cfg)

	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			_, _ = os.Stdout.Write(buf[:n])

			if !otpDone {
				if time.Now().After(deadline) {
					log.Debug("OTP deadline reached without seeing prompt")
					otpDone = true
				} else {
					acc.Write(buf[:n])
					if bytes.Contains(acc.Bytes(), []byte("Verification code:")) {
						log.Debug("OTP prompt detected, fetching code")
						code, err := callback()
						if err != nil {
							log.Fatal("Failed to get OTP", "error", err)
						}
						log.Debug("OTP obtained, sending")
						_, _ = fmt.Fprintf(ptmx, "%s\r", code)
						otpDone = true
					}
				}
			}
		}
		if err != nil {
			log.Debug("PTY read ended", "error", err)
			return
		}
	}
}
