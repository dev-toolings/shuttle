set -eu
install -d -m 0700 /etc/shuttle/setup.d
if [ ! -f /etc/shuttle/setup.d/10-base ]; then
export DEBIAN_FRONTEND=noninteractive
if command -v cloud-init >/dev/null 2>&1; then timeout 900 cloud-init status --wait >/dev/null 2>&1 || true; fi
printf 'DPkg::Lock::Timeout "600";\n' > /etc/apt/apt.conf.d/50shuttle-dpkg-lock
apt-get update -y
apt-get dist-upgrade -y
apt-get install -y ca-certificates curl gnupg sudo ufw fail2ban apparmor apparmor-utils unattended-upgrades openssh-server systemd-timesyncd
install -d -m 0755 /etc/apt/keyrings
printf '%s\n' 'APT::Periodic::Update-Package-Lists "1";' 'APT::Periodic::Unattended-Upgrade "1";' >/etc/apt/apt.conf.d/20auto-upgrades
systemctl enable --now apparmor fail2ban unattended-upgrades systemd-timesyncd
# Exempt the operator's own address from fail2ban.
#
# This stage installs fail2ban, and the SSH hardening that follows closes the
# first-contact account: on a host adopted as root, the signed baseline is
# "AllowUsers deploy" and root can no longer open a session. An operator who
# then retries root@ out of habit -- or whose tooling does -- spends five
# failed publickey auths and gets the SOURCE ADDRESS banned. fail2ban bans an
# IP, not an account, so the ban also severs the deploy@ access this very run
# just created, and the host becomes reachable only through the provider's
# out-of-band console.
#
# Measured on a real adoption (03-09-2026): five root@ attempts after the
# baseline applied, jail sshd reported "Currently banned: 1" with the
# operator's address, and every subsequent deploy@ connection was refused --
# on a host whose sshd was listening and whose UFW allowed 22/tcp. The
# deployment stalled there until someone opened a browser console.
#
# The operator is trusted by construction: they hold the key that signs every
# root operation on this host. Exempting the address they are converging from
# removes a trap Shuttle sets for itself. Addresses accumulate across runs, so
# adopting from a second workstation does not evict the first.
operator_ip="${SSH_CONNECTION:-}"
operator_ip="${operator_ip%% *}"
if [ -n "$operator_ip" ]; then
  install -d -m 0755 /etc/fail2ban/jail.d
  operator_jail=/etc/fail2ban/jail.d/10-shuttle-operator.conf
  ignored=""
  [ -f "$operator_jail" ] && ignored=$(sed -n 's/^ignoreip[[:space:]]*=[[:space:]]*//p' "$operator_jail" | head -1)
  [ -n "$ignored" ] || ignored="127.0.0.1/8 ::1"
  case " $ignored " in
    *" $operator_ip "*) ;;
    *) ignored="$ignored $operator_ip" ;;
  esac
  printf '%s\n' '# Written by shuttle setup: the operator address must never be banned.' '[DEFAULT]' "ignoreip = $ignored" >"$operator_jail"
  systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban 2>/dev/null || true
fi
if ! swapon --show=NAME --noheadings | grep -q .; then
  fallocate -l 2G /swapfile
  chmod 0600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  grep -Fqx '/swapfile none swap sw 0 0' /etc/fstab || printf '%s\n' '/swapfile none swap sw 0 0' >>/etc/fstab
fi

touch /etc/shuttle/setup.d/10-base
fi

# This drop-in is outside the 10-base checkpoint so a completed setup and
# adopted hosts converge to the policy doctor verifies on every invocation.
. /etc/os-release
case "$ID:$VERSION_ID" in
  ubuntu:24.04)
    unattended_policy='#clear Unattended-Upgrade::Allowed-Origins;\n#clear Unattended-Upgrade::Origins-Pattern;\nUnattended-Upgrade::Allowed-Origins { "${distro_id}:${distro_codename}-security"; "${distro_id}ESMApps:${distro_codename}-apps-security"; "${distro_id}ESM:${distro_codename}-infra-security"; };\nUnattended-Upgrade::Automatic-Reboot "false";'
    ;;
  debian:13)
    unattended_policy='#clear Unattended-Upgrade::Allowed-Origins;\n#clear Unattended-Upgrade::Origins-Pattern;\nUnattended-Upgrade::Origins-Pattern { "origin=Debian,codename=${distro_codename}-security,label=Debian-Security"; };\nUnattended-Upgrade::Automatic-Reboot "false";'
    ;;
  *) echo "unsupported unattended-upgrades policy for $ID $VERSION_ID" >&2; exit 1 ;;
esac
unattended_file=/etc/apt/apt.conf.d/52shuttle-unattended-upgrades
unattended_tmp=$(mktemp /etc/apt/apt.conf.d/.52shuttle-unattended-upgrades.XXXXXX)
printf '%b\n' "$unattended_policy" >"$unattended_tmp"
chmod 0644 "$unattended_tmp"
if ! cmp -s "$unattended_tmp" "$unattended_file"; then
  mv -f "$unattended_tmp" "$unattended_file"
else
  rm -f "$unattended_tmp"
fi
