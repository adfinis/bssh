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

	bastion "github.com/adfinis/bastion-go"
	"github.com/adfinis/bssh/config"
	"github.com/adfinis/bssh/otp"
	"github.com/charmbracelet/fang"
	"github.com/charmbracelet/log"
	"github.com/creack/pty"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

var (
	// Version is the current version of adfinis-rclone-mgr.
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
	PersistentPreRun: func(_ *cobra.Command, _ []string) {
		level, err := log.ParseLevel(rootCmdFlags.logLevel)
		if err != nil {
			log.Fatal("Invalid log level", "error", err)
		}
		log.SetLevel(level)
	},
	Run: root,
}

func init() {
	rootCmd.Flags().StringVarP(&rootCmdFlags.configPath, "config", "c", "", "Path to config file")
	rootCmd.Flags().StringVar(&rootCmdFlags.logLevel, "log-level", "info", "Log level (debug, info, warn, error, fatal)")

	rootCmd.Flags().String("username", "", "SSH username")
	rootCmd.Flags().String("hostname", "", "SSH hostname")
	rootCmd.Flags().Int("port", 0, "SSH port")
	rootCmd.Flags().String("ssh-command", "", "SSH command (default \"ssh -t\")")
	rootCmd.Flags().String("otp-callback-command", "", "Command to obtain OTP code")
	rootCmd.Flags().String("otp-shell-command", "", "Shell command to run OTP callback (default \"/usr/bin/env bash -c\")")

	v := config.GetViper()
	_ = v.BindPFlag("username", rootCmd.Flags().Lookup("username"))
	_ = v.BindPFlag("hostname", rootCmd.Flags().Lookup("hostname"))
	_ = v.BindPFlag("port", rootCmd.Flags().Lookup("port"))
	_ = v.BindPFlag("ssh_command", rootCmd.Flags().Lookup("ssh-command"))
	_ = v.BindPFlag("otp_callback_command", rootCmd.Flags().Lookup("otp-callback-command"))
	_ = v.BindPFlag("otp_shell_command", rootCmd.Flags().Lookup("otp-shell-command"))
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
		"otp_shell_command", cfg.OTPShellCommand,
		"otp_callback_command", cfg.OTPCallbackCommand,
	)

	sshParts := strings.Fields(cfg.SSHCommand)
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
	otpDone := false
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

// completeHosts provides shell completion for bastion host targets.
// It uses the bastion-go library to query available accesses via the Bastion API.
func completeHosts(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	cfg, err := config.Load(rootCmdFlags.configPath)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	client, err := bastion.New(
		&bastion.Config{
			Host:     cfg.Hostname,
			Port:     cfg.Port,
			Username: cfg.Username,
		},
		bastion.WithSSHAgentAuth(),
		otp.WithAuth(cfg),
	)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	accesses, err := client.SelfListAccesses()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	seen := make(map[string]struct{})
	var hosts []string
	for _, access := range accesses {
		for _, acl := range access.ACL {
			if _, ok := seen[acl.IP]; ok {
				continue
			}
			seen[acl.IP] = struct{}{}

			value := acl.IP
			if acl.ProxyIP != nil && *acl.ProxyIP != "" {
				jump := *acl.ProxyIP
				if acl.ProxyUser != nil && *acl.ProxyUser != "" {
					jump = *acl.ProxyUser + "@" + jump
				}
				if acl.ProxyPort != nil && acl.ProxyPort.ValueInt() > 0 {
					jump = fmt.Sprintf("%s:%d", jump, acl.ProxyPort.ValueInt())
				}
				value = fmt.Sprintf("%s -J %s", jump, acl.IP)
			}

			entry := value
			if acl.UserComment != nil && *acl.UserComment != "" {
				entry = fmt.Sprintf("%s\t%s", value, *acl.UserComment)
			}
			hosts = append(hosts, entry)
		}
	}

	return hosts, cobra.ShellCompDirectiveNoFileComp
}
