package cli

import (
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func connectSSH(group config.ServerGroup, host string) (*ssh.Client, error) {
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return nil, err
	}
	return ssh.NewClientExactWithFingerprint(host, group.User, group.Port, identity.HostKeyFingerprint)
}
