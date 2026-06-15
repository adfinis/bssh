# BSSH

SSH for The Bastion with fancy autocompletion and OTP callback support.

## Build / Install

```bash
# to build the project:
go build .

# to install with go directly:
go install .

# Arch (btw):
yay -S bssh-bin

# Other linux distros might find a more suitable solution in the release tab of this repository
```

## Usage

```
bssh [flags] -- <command>
```

## Configuration

bssh looks for a `config.yml` file in the following locations (in order):

1. Current directory (`.`)
2. `$XDG_CONFIG_HOME/bssh/`
3. `/etc/bssh/`

All config values can be overridden with environment variables using the `BSSH_` prefix (e.g. `BSSH_USERNAME`).

### Options

| Option | Description | Default | Required |
|---|---|---|---|
| `username` | SSH username | — | Yes |
| `hostname` | SSH hostname | — | Yes |
| `port` | SSH Port | 22 | No |
| `ssh_command` | SSH command to use | `ssh -t` | No |
| `otp_enabled` | Enable the OTP callback | `false` | No |
| `otp_callback_command` | Command that outputs the OTP code | — | Yes, if `otp_enabled` |
| `otp_shell_command` | Shell used to run the OTP callback | `/usr/bin/env bash -c` | No |
| `openbao.enabled` | Sign an SSH key with the OpenBao SSH engine and log in with the certificate | `false` | No |
| `openbao.address` | OpenBao server address (URL) | — | Yes, if `openbao.enabled` |
| `openbao.mount_path` | Mount path of the SSH secrets engine | `ssh` | No |
| `openbao.role` | SSH engine role used to sign the key | — | Yes, if `openbao.enabled` |
| `openbao.public_key` | Path to the SSH public key to sign | — | Yes, if `openbao.enabled` |
| `openbao.private_key` | Path to the matching private key | public key without `.pub` | No |
| `openbao.cert_output` | Path to write the signed certificate | temporary file | No |

OTP and OpenBao certificate signing are independent, opt-in features. Enable
either, both, or neither.

### OTP example

```yaml
username: myuser
hostname: bastion.example.com
otp_enabled: true
otp_callback_command: ykman oath accounts code "Bastion" | cut -d" " -f3
```

### OpenBao certificate example

When `openbao.enabled` is set, bssh asks the OpenBao SSH secrets engine to sign
the configured public key and logs in to the bastion with the resulting
short-lived certificate (passed to `ssh` via `CertificateFile`/`IdentityFile`).

The OpenBao token is taken from `BAO_TOKEN`/`VAULT_TOKEN` or, failing that, the
standard token file (`~/.bao-token` or `~/.vault-token`, e.g. created by
`bao login`). The server address can also be provided via the `BAO_ADDR`
environment variable instead of `openbao.address`.

```yaml
username: myuser
hostname: bastion.example.com
openbao:
  enabled: true
  address: https://bao.example.com:8200
  mount_path: ssh
  role: bastion
  public_key: ~/.ssh/id_ed25519.pub
```
