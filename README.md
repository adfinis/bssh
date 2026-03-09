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
| `otp_callback_command` | Command that outputs the OTP code | — | Yes |
| `ssh_command` | SSH command to use | `ssh -t` | No |
| `otp_shell_command` | Shell used to run the OTP callback | `/usr/bin/env bash -c` | No |

### Example

```yaml
username: myuser
hostname: bastion.example.com
otp_callback_command: ykman oath accounts code "Bastion" | cut -d" " -f3
```
