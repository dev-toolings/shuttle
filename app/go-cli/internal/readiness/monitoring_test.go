package readiness

import "testing"

func TestMonitoringSSHMatchesEveryRequiredContextShape(t *testing.T) {
	body := "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\nport 2222\nallowusers deploy ops\n"
	if !MonitoringSSHMatches(body, []string{"ops", "deploy"}, 2222) {
		t.Fatal("safe effective SSH context was rejected")
	}
	if MonitoringSSHMatches("permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\nport 2222\nallowusers deploy\n", []string{"ops", "deploy"}, 2222) {
		t.Fatal("SSH context drift for a required account was accepted")
	}
}

func TestMonitoringUFWRequiresExplicitIncomingAndRoutedPolicies(t *testing.T) {
	safe := "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), deny (routed)\n"
	if !MonitoringUFWAllowsOnlySafeDefaults(safe) {
		t.Fatal("verbose deny incoming / allow outgoing / deny routed was rejected")
	}
	if MonitoringUFWAllowsOnlySafeDefaults("Status: active\n") {
		t.Fatal("active UFW without Default was accepted")
	}
	if MonitoringUFWAllowsOnlySafeDefaults("Status: active\nDefault: deny (incoming), allow (outgoing), allow (routed)\n") {
		t.Fatal("permissive routed third field was accepted")
	}
	if MonitoringUFWAllowsOnlySafeDefaults("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n") {
		t.Fatal("ambiguous disabled routed policy was accepted")
	}
}

func TestMonitoringUFWAndDockerUserRejectBypassFixtures(t *testing.T) {
	if MonitoringUFWAllowsOnlySafeDefaults("Status: active\nDefault: allow (incoming), deny (outgoing), disabled (routed)\n") {
		t.Fatal("active UFW allow-all default was accepted")
	}
	unsafe := "-N DOCKER-USER\n-A DOCKER-USER -j ACCEPT\n-A DOCKER-USER -j ufw-before-forward\n-A DOCKER-USER -j RETURN\n"
	if MonitoringDockerUserOrder(unsafe, unsafe) {
		t.Fatal("unconditional Docker-USER bypass before UFW was accepted")
	}
}

func TestMonitoringIPv6ListenerBridgeRejectsPublicPort(t *testing.T) {
	line := "LISTEN 0 128 [::]:5000 [::]:*"
	if !MonitoringValidListenerEvidence(line) {
		t.Fatal("valid IPv6 listener evidence was rejected")
	}
	if !MonitoringPublicListenerPort(line, "5000") {
		t.Fatal("public IPv6 listener was not detected")
	}
}
