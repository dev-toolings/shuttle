package cli

import (
	"encoding/json"
	"fmt"
	"strings"
)

// caddyEffectiveSiteHosts extracts host matchers from Caddy's adapted JSON.
// The adapter has already expanded imports, so probes follow the configuration
// the running edge actually loads rather than one guessed fragment directory.
func caddyEffectiveSiteHosts(adapted []byte) ([]string, error) {
	var config any
	if err := json.Unmarshal(adapted, &config); err != nil {
		return nil, fmt.Errorf("decode adapted Caddy configuration: %w", err)
	}
	var hosts []string
	var visit func(any) error
	visit = func(value any) error {
		switch typed := value.(type) {
		case map[string]any:
			if matcher, found := typed["host"]; found {
				values, ok := matcher.([]any)
				if !ok {
					return fmt.Errorf("adapted Caddy host matcher has type %T", matcher)
				}
				for _, value := range values {
					host, ok := value.(string)
					if !ok {
						return fmt.Errorf("adapted Caddy host matcher contains %T", value)
					}
					hosts = append(hosts, host)
				}
			}
			for key, child := range typed {
				if key == "host" {
					continue
				}
				if err := visit(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range typed {
				if err := visit(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(config); err != nil {
		return nil, err
	}
	return sortedUnique(hosts), nil
}

// caddyFragmentSiteAddresses reads the simple site headers used by Shuttle's
// generated fragments. Root route collision checks use this before Caddy loads
// a new fragment, so they do not depend on a running edge container.
func caddyFragmentSiteAddresses(fragment string) []string {
	var addresses []string
	for _, line := range strings.Split(fragment, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		head, _, found := strings.Cut(strings.TrimSpace(line), "{")
		if !found {
			continue
		}
		for _, address := range strings.Split(head, ",") {
			if address = strings.TrimSpace(address); address != "" {
				addresses = append(addresses, address)
			}
		}
	}
	return addresses
}
