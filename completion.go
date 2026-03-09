package main

import (
	"fmt"
	"strings"

	"github.com/adfinis/bastion-go"
	"github.com/adfinis/bssh/config"
	"github.com/adfinis/bssh/otp"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
)

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
			// skip protocl acls
			if acl.User != nil && strings.HasPrefix(*acl.User, "!") {
				continue
			}

			var portInt, proxyPortInt int
			if acl.Port != nil {
				portInt = acl.Port.ValueInt()
			}
			if acl.ProxyPort != nil {
				proxyPortInt = acl.ProxyPort.ValueInt()
			}
			aclkey := fmt.Sprintf("%s|%d|%s|%s|%d|%s",
				acl.IP,
				portInt,
				lo.FromPtr(acl.User),
				lo.FromPtr(acl.ProxyIP),
				proxyPortInt,
				lo.FromPtr(acl.ProxyUser),
			)

			if _, ok := seen[aclkey]; ok {
				continue
			}
			seen[aclkey] = struct{}{}

			value := acl.IP
			if acl.ProxyIP != nil && *acl.ProxyIP != "" {
				jump := *acl.ProxyIP
				if acl.ProxyUser != nil && *acl.ProxyUser != "" {
					jump = *acl.ProxyUser + "@" + jump
				}
				if acl.ProxyPort != nil && acl.ProxyPort.ValueInt() > 0 {
					jump = fmt.Sprintf("%s:%d", jump, acl.ProxyPort.ValueInt())
				}
				value = fmt.Sprintf("%s -J %s", acl.IP, jump)
			}

			if acl.User != nil &&
				!strings.Contains(*acl.User, "*") &&
				!strings.Contains(*acl.User, "?") &&
				!strings.Contains(*acl.User, "!") {
				value = fmt.Sprintf("%s -l %s", value, *acl.User)
			}

			if acl.Port != nil && acl.Port.ValueInt() > 0 && acl.Port.ValueInt() != 22 {
				value = fmt.Sprintf("%s -p %d", value, acl.Port.ValueInt())
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
