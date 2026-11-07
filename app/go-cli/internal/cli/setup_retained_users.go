package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/shell"
)

// Retained accounts are the answer to a host that is not one person's.
//
// The signed SSH baseline names exactly who may log in, and until now that was
// deploy, the declared operator, and under adoption the account the run arrived
// on. Everyone else with a key on the host lost SSH the moment `setup`
// committed, and nothing in the plan said so — a colleague found out at their
// next login, on a shared pre-production host whose Compose path they were
// still deploying through. The remedy was rebuilding the host by hand.
//
// A retained account is signed into AllowUsers and nothing else happens to it.
// Shuttle creates none, installs no key, writes no sudo rule and leaves group
// memberships alone: the account keeps exactly the access it had, including a
// docker or sudo membership that is root-equivalent today and stays so. That is
// the operator's decision to make, and the plan states it rather than hiding
// it. An account that should be *changed* — given a managed sudo rule, its
// groups reduced — is the operator, not a retained user.

// resolveSetupRetainedUsers merges --retain-user flags into the configured
// list and validates the result exactly as the configuration loader does. The
// merge happens after the configuration was validated, so the merged list is
// checked again: a flag is one more way for an unchecked name to reach an sshd
// directive.
func resolveSetupRetainedUsers(cfg *config.Config, options setupOptions, operator *setupOperatorAccess) ([]string, error) {
	// Deduplicated across the two sources before validation: a flag naming an
	// account the configuration already retains states the same intent twice,
	// which is not the repeat inside one list that the loader refuses.
	users := sortedUnique(append(append([]string(nil), cfg.Setup.RetainedUsers...), options.retainUsers...))
	operatorUser := ""
	if operator != nil {
		operatorUser = operator.user
	}
	if err := config.ValidateRetainedUsers(users, operatorUser); err != nil {
		return nil, err
	}
	return users, nil
}

// setupRetainedUsersPreflightCommand is the read-only check that a retained
// account can actually survive the hardening it is being retained through.
//
// The baseline closes password and keyboard-interactive logins, so an account
// with no valid public key would be signed into AllowUsers and still be locked
// out — with the plan saying the opposite. The check therefore refuses, before
// anything is changed, an account that does not exist, is a system account,
// has no login shell, or has no authorized_keys file holding at least one key
// ssh-keygen can parse. Every refusal names the account and the reason, because
// the operator fixes it on the host and needs to know where.
//
// Nothing here writes: `id`, `getent`, `test` and `ssh-keygen -l` only read.
func setupRetainedUsersPreflightCommand(users []string) string {
	if len(users) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(users))
	for _, user := range users {
		quoted = append(quoted, shell.Escape(user))
	}
	return "set -eu\nfor user in " + strings.Join(quoted, " ") + `; do
  if ! id "$user" >/dev/null 2>&1; then
    echo "retained account $user does not exist on this host" >&2
    exit 1
  fi
  uid=$(id -u "$user")
  if [ "$uid" -lt 1000 ] || [ "$uid" -ge 65534 ]; then
    echo "retained account $user is a system account (uid $uid), not a login" >&2
    exit 1
  fi
  case "$(getent passwd "$user" | cut -d: -f7)" in
    /bin/bash|/bin/sh|/bin/dash|/bin/zsh|/usr/bin/bash|/usr/bin/zsh) ;;
    *) echo "retained account $user has no login shell" >&2; exit 1;;
  esac
  home=$(getent passwd "$user" | cut -d: -f6)
  keys="$home/.ssh/authorized_keys"
  if [ -L "$keys" ] || [ ! -f "$keys" ]; then
    echo "retained account $user has no $keys; setup closes password logins, so it would be signed into AllowUsers and still be locked out" >&2
    exit 1
  fi
  if ! ssh-keygen -lf "$keys" >/dev/null 2>&1; then
    echo "retained account $user: $keys holds no public key ssh-keygen can read" >&2
    exit 1
  fi
done
`
}

func preflightSetupRetainedUsers(runner setupRunner, users []string) error {
	if len(users) == 0 {
		return nil
	}
	if result := runner.run(setupRetainedUsersPreflightCommand(users)); result.Code != 0 {
		return fmt.Errorf("retained account failed read-only preflight: %s", strings.TrimSpace(result.Stderr))
	}
	return nil
}

// refuseRetainedFirstContactLockOut catches a configuration that says two
// things about one account: --lock-out-first-contact-user removes the login
// this adoption arrived on, and retaining that same login keeps it.
func refuseRetainedFirstContactLockOut(identity setupIdentity, options setupOptions) error {
	if !options.lockOutFirstContactUser {
		return nil
	}
	for _, user := range options.retained {
		if user == identity.user {
			return errors.New("--lock-out-first-contact-user removes " + user + ", and retaining it keeps it; drop one of the two")
		}
	}
	return nil
}

// setupExtraSSHUsers is the fresh-setup list signed beside deploy: the operator
// and the retained accounts. With neither it is nil, so the baseline a host
// converged from scratch receives is the one it always received.
func setupExtraSSHUsers(operator *setupOperatorAccess, retained []string) []string {
	users := append([]string(nil), retained...)
	if operator != nil {
		users = append(users, operator.user)
	}
	return sortedUnique(users)
}

// adoptionSignedSSHUsers is every account beyond deploy the adoption baseline
// keeps: the administrators whose login is proven (adoptionPreservedSSHUsers)
// plus the retained accounts, whose login is not — Shuttle holds no private key
// of theirs — and which therefore must not enter the proof loops.
func adoptionSignedSSHUsers(identity setupIdentity, options setupOptions) []string {
	return sortedUnique(append(adoptionPreservedSSHUsers(identity, options), options.retained...))
}

// setupRetainedUsersSummary is what the plan and the final report say about the
// accounts left in place. It is empty when there are none, so every existing
// output stays byte-identical.
func setupRetainedUsersSummary(identity setupIdentity, users []string) string {
	if len(users) == 0 {
		return ""
	}
	var out strings.Builder
	for _, user := range users {
		fmt.Fprintf(&out, "Retained %s: ssh -p %d %s@%s with its existing key; groups, sudo rules and home are left as they are.\n", user, identity.port, user, identity.host)
	}
	out.WriteString("Retained accounts are signed into AllowUsers and otherwise untouched: a docker or sudo membership they hold today is root-equivalent access Shuttle neither grants nor removes. Their login is not proven here — no private key of theirs is held on this machine — only that each has a readable public key and that sshd enforces the signed list.\n")
	return out.String()
}
