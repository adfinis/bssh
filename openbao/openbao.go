package openbao

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	bastion "github.com/adfinis/bastion-go"
	"github.com/adfinis/bssh/config"
	bao "github.com/openbao/openbao/api/v2"
	"golang.org/x/crypto/ssh"
)

// SignedCert is the result of signing an SSH key with the OpenBao SSH engine.
type SignedCert struct {
	// Certificate is the signed certificate in authorized_keys format.
	Certificate string
	// PublicKey is the path to the public key that was signed.
	PublicKey string
	// PrivateKey is the path to the matching private key.
	PrivateKey string
}

// Sign requests a signed SSH certificate for the configured public key from the
// OpenBao SSH secrets engine.
func Sign(cfg *config.Config) (*SignedCert, error) {
	pubPath := expandPath(cfg.OpenBao.PublicKey)
	pubKey, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key %q: %w", pubPath, err)
	}

	client, err := newClient(cfg)
	if err != nil {
		return nil, err
	}

	secret, err := client.SSHWithMountPoint(cfg.OpenBao.MountPath).SignKey(cfg.OpenBao.Role, map[string]any{
		"public_key": string(pubKey),
		"ttl":        cfg.OpenBao.TTL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign SSH key: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("OpenBao returned no data for SSH signing")
	}

	signed, ok := secret.Data["signed_key"].(string)
	if !ok || signed == "" {
		return nil, fmt.Errorf("OpenBao response did not contain a signed_key")
	}

	return &SignedCert{
		Certificate: signed,
		PublicKey:   pubPath,
		PrivateKey:  privateKeyPath(cfg),
	}, nil
}

// Write writes the certificate to the configured output path, or to a temporary
// file if no path is configured. It returns the path to the written certificate
// and a cleanup function that removes the temporary file (a no-op for a
// configured path).
func (s *SignedCert) Write(cfg *config.Config) (string, func(), error) {
	if cfg.OpenBao.CertOutput != "" {
		path := expandPath(cfg.OpenBao.CertOutput)
		if err := os.WriteFile(path, []byte(s.Certificate), 0o600); err != nil {
			return "", nil, fmt.Errorf("failed to write certificate to %q: %w", path, err)
		}
		return path, func() {}, nil
	}

	f, err := os.CreateTemp("", "bssh-cert-*.pub")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temporary certificate file: %w", err)
	}
	if _, err := f.WriteString(s.Certificate); err != nil {
		_ = f.Close()           //nolint:errcheck
		_ = os.Remove(f.Name()) //nolint:errcheck
		return "", nil, fmt.Errorf("failed to write certificate: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name()) //nolint:errcheck
		return "", nil, fmt.Errorf("failed to write certificate: %w", err)
	}

	return f.Name(), func() {
		_ = os.Remove(f.Name()) //nolint:errcheck
	}, nil
}

// WithAuth returns a bastion-go SSHAuthMethod that signs the configured key with
// OpenBao and authenticates using the resulting certificate together with its
// matching private key.
func WithAuth(cfg *config.Config) bastion.SSHAuthMethod {
	return func() (ssh.AuthMethod, error) {
		signed, err := Sign(cfg)
		if err != nil {
			return nil, err
		}

		keyBytes, err := os.ReadFile(signed.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key %q: %w", signed.PrivateKey, err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key %q: %w", signed.PrivateKey, err)
		}

		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signed.Certificate))
		if err != nil {
			return nil, fmt.Errorf("failed to parse signed certificate: %w", err)
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("signed key is not an SSH certificate")
		}

		certSigner, err := ssh.NewCertSigner(cert, signer)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate signer: %w", err)
		}
		return ssh.PublicKeys(certSigner), nil
	}
}

// newClient builds an OpenBao API client using the configured address and a
// token resolved from the environment or the standard token file.
func newClient(cfg *config.Config) (*bao.Client, error) {
	apiCfg := bao.DefaultConfig()
	if apiCfg.Error != nil {
		return nil, fmt.Errorf("failed to load OpenBao client config: %w", apiCfg.Error)
	}
	if cfg.OpenBao.Address != "" {
		apiCfg.Address = cfg.OpenBao.Address
	}

	client, err := bao.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenBao client: %w", err)
	}

	if client.Token() == "" {
		token, err := resolveToken()
		if err != nil {
			return nil, err
		}
		client.SetToken(token)
	}

	return client, nil
}

// resolveToken looks for an OpenBao token in the environment and, failing that,
// in the standard token helper file in the user's home directory.
func resolveToken() (string, error) {
	for _, env := range []string{"BAO_TOKEN", "VAULT_TOKEN"} {
		if t := strings.TrimSpace(os.Getenv(env)); t != "" {
			return t, nil
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to determine home directory for token file: %w", err)
	}
	for _, name := range []string{".bao-token", ".vault-token"} {
		data, err := os.ReadFile(filepath.Join(home, name))
		if err != nil {
			continue
		}
		if t := strings.TrimSpace(string(data)); t != "" {
			return t, nil
		}
	}

	return "", fmt.Errorf("no OpenBao token found: set BAO_TOKEN/VAULT_TOKEN or log in to create a token file")
}

// privateKeyPath returns the configured private key path, defaulting to the
// public key path with the .pub suffix removed.
func privateKeyPath(cfg *config.Config) string {
	if cfg.OpenBao.PrivateKey != "" {
		return expandPath(cfg.OpenBao.PrivateKey)
	}
	return strings.TrimSuffix(expandPath(cfg.OpenBao.PublicKey), ".pub")
}

// expandPath expands a leading ~/ to the user's home directory.
func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
