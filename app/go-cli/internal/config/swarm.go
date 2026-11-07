package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

func validateSwarmTopology(value Swarm, groups map[string]ServerGroup) error {
	if value.Replicas < 0 {
		return fmt.Errorf("deploy.swarm.replicas must not be negative")
	}
	mode := strings.TrimSpace(value.Mode)
	if mode == "" {
		mode = "single-node"
	}
	if mode != "single-node" && mode != "multi-node" {
		return fmt.Errorf("deploy.swarm.mode %q is invalid: expected single-node or multi-node", value.Mode)
	}
	if mode == "single-node" {
		if len(value.Nodes) > 0 {
			return fmt.Errorf("deploy.swarm.nodes requires mode: multi-node")
		}
		return nil
	}
	if len(value.Nodes) < 2 {
		return fmt.Errorf("deploy.swarm.nodes must contain at least two nodes in multi-node mode")
	}
	managerCount := 0
	seen := map[string]bool{}
	declaredGroup := ""
	for index, node := range value.Nodes {
		host := strings.TrimSpace(node.Host)
		if host == "" {
			return fmt.Errorf("deploy.swarm.nodes[%d].host is required", index)
		}
		if seen[host] {
			return fmt.Errorf("deploy.swarm.nodes contains duplicate host %q", host)
		}
		seen[host] = true
		if node.Role != "manager" && node.Role != "worker" {
			return fmt.Errorf("deploy.swarm.nodes[%d].role %q is invalid: expected manager or worker", index, node.Role)
		}
		if node.Role == "manager" {
			managerCount++
		}
		if node.AdvertiseAddr != "" && net.ParseIP(strings.TrimSpace(node.AdvertiseAddr)) == nil {
			return fmt.Errorf("deploy.swarm.nodes[%d].advertise_addr must be a literal IP address", index)
		}
		memberGroups := make([]string, 0, 1)
		for groupName, group := range groups {
			for _, configured := range group.Hosts {
				if strings.TrimSpace(configured) == host {
					memberGroups = append(memberGroups, groupName)
				}
			}
		}
		if len(memberGroups) == 0 {
			return fmt.Errorf("deploy.swarm.nodes[%d].host %q is not present in any servers.<name>.hosts", index, host)
		}
		if len(memberGroups) > 1 {
			return fmt.Errorf("deploy.swarm.nodes[%d].host %q appears in multiple server groups", index, host)
		}
		if declaredGroup == "" {
			declaredGroup = memberGroups[0]
		} else if declaredGroup != memberGroups[0] {
			return fmt.Errorf("deploy.swarm.nodes must belong to one servers.<name> group; found %q and %q", declaredGroup, memberGroups[0])
		}
	}
	if managerCount == 0 {
		return fmt.Errorf("deploy.swarm.nodes must contain at least one manager")
	}
	if value.Nodes[0].Role != "manager" {
		return errors.New("deploy.swarm.nodes must list a manager first for deterministic bootstrap")
	}
	return nil
}
