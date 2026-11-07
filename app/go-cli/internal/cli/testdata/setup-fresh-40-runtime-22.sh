set -eu
install -d -m 0700 /etc/shuttle/setup.d
if [ ! -f /etc/shuttle/setup.d/40-runtime ]; then
id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/bash deploy
# useradd leaves the home at the distribution default (0750 on Ubuntu), which
# the readiness check for this very account then fails on. The mode is set here
# so a freshly set up host does not audit dirty on its own doing.
install -d -o deploy -g deploy -m 0700 /home/deploy
install -d -o deploy -g deploy -m 0700 /home/deploy/.ssh
install -o deploy -g deploy -m 0600 /tmp/shuttle-operator.pub /home/deploy/.ssh/authorized_keys
gpasswd -d deploy sudo >/dev/null 2>&1 || true
gpasswd -d deploy docker >/dev/null 2>&1 || true
install -d -m 0755 /usr/local/libexec /etc/shuttle
install -o root -g root -m 0755 /tmp/shuttle-root /usr/local/libexec/shuttle-root
install -o root -g root -m 0444 /tmp/shuttle-root-trust.pem /etc/shuttle/trusted-root-operations.pem
install -d -m 0755 /etc/systemd/resolved.conf.d
printf '%s\n' '[Resolve]' 'LLMNR=no' 'MulticastDNS=no' >/etc/systemd/resolved.conf.d/60-shuttle.conf
systemctl restart systemd-resolved
printf '%s\n' '[sshd]' 'enabled = true' 'port = 22' >/etc/fail2ban/jail.d/shuttle-sshd.local
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
gateway=$(docker network inspect docker_gwbridge --format '{{(index .IPAM.Config 0).Gateway}}')
subnet=$(docker network inspect docker_gwbridge --format '{{(index .IPAM.Config 0).Subnet}}')
if [ -n "$gateway" ] && [ -n "$subnet" ]; then
  ufw allow from "$subnet" to "$gateway" port 5432 proto tcp
else
  echo 'cannot determine the Docker gateway; the managed database would be unreachable from every container' >&2
  exit 1
fi
cat >/usr/local/libexec/shuttle-docker-user-firewall <<'SHUTTLE_DOCKER_FIREWALL'
#!/bin/sh
set -eu
iptables=/usr/sbin/iptables
# UFW starts before networking and Docker at boot. There is no forwarding
# policy to apply until Docker creates this chain; the ordered systemd service
# applies it after Docker starts. A live chain still requires a valid route.
"$iptables" -S DOCKER-USER >/dev/null 2>&1 || exit 0
# The interface the default route leaves by is what "outside" means on this
# host. Derived rather than assumed: eth0 is a convention, not a guarantee.
external=$(ip -o -4 route show default | awk '{print $5; exit}')
if [ -z "$external" ]; then
  echo 'cannot determine the external interface; refusing to install a policy that would filter east-west traffic' >&2
  exit 1
fi
if ! "$iptables" -S ufw-user-forward >/dev/null 2>&1; then
  echo 'UFW user-forward chain is unavailable' >&2
  exit 1
fi
if "$iptables" -S ufw-docker-logging-deny >/dev/null 2>&1; then
  "$iptables" -F ufw-docker-logging-deny
else
  "$iptables" -N ufw-docker-logging-deny
fi
"$iptables" -F DOCKER-USER
"$iptables" -A DOCKER-USER -j ufw-user-forward
"$iptables" -A DOCKER-USER -p udp --sport 53 --dport 1024:65535 -j RETURN
# The edge publishes 80/443, and Docker DNATs those connections to the Caddy
# container, whose address lives inside the private ranges denied below. Without
# these three rules the deny list silently blackholes the shared edge, so a
# freshly set-up VPS answers SSH and nothing else: the site is unreachable and
# ACME can never complete its HTTP-01 or TLS-ALPN-01 challenge. Allow exactly the
# published edge ports, before the private-range denies, and nothing more.
"$iptables" -A DOCKER-USER -p tcp --dport 80 --tcp-flags FIN,SYN,RST,ACK SYN -j RETURN
"$iptables" -A DOCKER-USER -p tcp --dport 443 --tcp-flags FIN,SYN,RST,ACK SYN -j RETURN
"$iptables" -A DOCKER-USER -p udp --dport 443 -j RETURN
# DOCKER-USER governs what may enter from outside. The rules below match on
# destination alone, and DOCKER-USER is traversed by every forwarded packet —
# including the ones that never came from outside. With br_netfilter, traffic
# between two containers of the same bridge crosses FORWARD too, and it does so
# before Docker's own per-bridge ACCEPT rules. So a deny list written for
# ingress silently cut east-west traffic: an application could not reach its own
# database, a front end could not reach its API, and a container could not reach
# a service on the LAN. Nothing looked wrong — container healthchecks probe
# 127.0.0.1 inside their own namespace and never cross this chain — so the host
# reported healthy while returning 502 to every real request.
#
# Anything that did not arrive on the external interface is therefore not
# ingress, and this chain has no business filtering it.
"$iptables" -A DOCKER-USER ! -i "$external" -j RETURN
"$iptables" -A DOCKER-USER -d 10.0.0.0/8 -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 172.16.0.0/12 -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 192.168.0.0/16 -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 10.0.0.0/8 -p udp --dport 0:32767 -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 172.16.0.0/12 -p udp --dport 0:32767 -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 192.168.0.0/16 -p udp --dport 0:32767 -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -j RETURN
"$iptables" -A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix '[UFW DOCKER BLOCK] '
"$iptables" -A ufw-docker-logging-deny -j DROP
SHUTTLE_DOCKER_FIREWALL
chmod 0755 /usr/local/libexec/shuttle-docker-user-firewall
cat >/etc/ufw/after.init <<'SHUTTLE_UFW_AFTER_INIT'
#!/bin/sh
set -eu
case "${1:-}" in
  start) /usr/local/libexec/shuttle-docker-user-firewall ;;
  stop|status|flush-all) ;;
  *) echo "Usage: after.init {start|stop|flush-all|status}" >&2; exit 1 ;;
esac
SHUTTLE_UFW_AFTER_INIT
chmod 0755 /etc/ufw/after.init
cat >/etc/systemd/system/shuttle-docker-user-firewall.service <<'SHUTTLE_DOCKER_FIREWALL_UNIT'
[Unit]
Description=Apply Shuttle UFW policy to Docker forwarding
After=ufw.service docker.service
Requires=docker.service
Wants=ufw.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/shuttle-docker-user-firewall
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SHUTTLE_DOCKER_FIREWALL_UNIT
systemctl daemon-reload
ufw --force enable
systemctl enable --now shuttle-docker-user-firewall.service
systemctl restart fail2ban
printf 'version=2\n' >/etc/shuttle/setup-state

touch /etc/shuttle/setup.d/40-runtime
fi
set -eu
install -d -m 0700 /etc/shuttle/setup.d
if [ ! -f /etc/shuttle/setup.d/41-firewall-boot ]; then
(
set -eu
policy=/usr/local/libexec/shuttle-docker-user-firewall
if [ ! -f "$policy" ] || [ -L "$policy" ]; then
  echo 'managed Docker firewall script is missing or symlinked; refusing automatic migration' >&2
  exit 1
fi
work=$(mktemp -d /usr/local/libexec/.shuttle-firewall.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cat >"$work/current" <<'SHUTTLE_FIREWALL_CURRENT'
#!/bin/sh
set -eu
iptables=/usr/sbin/iptables
# UFW starts before networking and Docker at boot. There is no forwarding
# policy to apply until Docker creates this chain; the ordered systemd service
# applies it after Docker starts. A live chain still requires a valid route.
"$iptables" -S DOCKER-USER >/dev/null 2>&1 || exit 0
# The interface the default route leaves by is what "outside" means on this
# host. Derived rather than assumed: eth0 is a convention, not a guarantee.
external=$(ip -o -4 route show default | awk '{print $5; exit}')
if [ -z "$external" ]; then
  echo 'cannot determine the external interface; refusing to install a policy that would filter east-west traffic' >&2
  exit 1
fi
if ! "$iptables" -S ufw-user-forward >/dev/null 2>&1; then
  echo 'UFW user-forward chain is unavailable' >&2
  exit 1
fi
if "$iptables" -S ufw-docker-logging-deny >/dev/null 2>&1; then
  "$iptables" -F ufw-docker-logging-deny
else
  "$iptables" -N ufw-docker-logging-deny
fi
"$iptables" -F DOCKER-USER
"$iptables" -A DOCKER-USER -j ufw-user-forward
"$iptables" -A DOCKER-USER -p udp --sport 53 --dport 1024:65535 -j RETURN
# The edge publishes 80/443, and Docker DNATs those connections to the Caddy
# container, whose address lives inside the private ranges denied below. Without
# these three rules the deny list silently blackholes the shared edge, so a
# freshly set-up VPS answers SSH and nothing else: the site is unreachable and
# ACME can never complete its HTTP-01 or TLS-ALPN-01 challenge. Allow exactly the
# published edge ports, before the private-range denies, and nothing more.
"$iptables" -A DOCKER-USER -p tcp --dport 80 --tcp-flags FIN,SYN,RST,ACK SYN -j RETURN
"$iptables" -A DOCKER-USER -p tcp --dport 443 --tcp-flags FIN,SYN,RST,ACK SYN -j RETURN
"$iptables" -A DOCKER-USER -p udp --dport 443 -j RETURN
# DOCKER-USER governs what may enter from outside. The rules below match on
# destination alone, and DOCKER-USER is traversed by every forwarded packet —
# including the ones that never came from outside. With br_netfilter, traffic
# between two containers of the same bridge crosses FORWARD too, and it does so
# before Docker's own per-bridge ACCEPT rules. So a deny list written for
# ingress silently cut east-west traffic: an application could not reach its own
# database, a front end could not reach its API, and a container could not reach
# a service on the LAN. Nothing looked wrong — container healthchecks probe
# 127.0.0.1 inside their own namespace and never cross this chain — so the host
# reported healthy while returning 502 to every real request.
#
# Anything that did not arrive on the external interface is therefore not
# ingress, and this chain has no business filtering it.
"$iptables" -A DOCKER-USER ! -i "$external" -j RETURN
"$iptables" -A DOCKER-USER -d 10.0.0.0/8 -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 172.16.0.0/12 -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 192.168.0.0/16 -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 10.0.0.0/8 -p udp --dport 0:32767 -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 172.16.0.0/12 -p udp --dport 0:32767 -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 192.168.0.0/16 -p udp --dport 0:32767 -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -j RETURN
"$iptables" -A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix '[UFW DOCKER BLOCK] '
"$iptables" -A ufw-docker-logging-deny -j DROP
SHUTTLE_FIREWALL_CURRENT
cat >"$work/legacy" <<'SHUTTLE_FIREWALL_LEGACY'
#!/bin/sh
set -eu
iptables=/usr/sbin/iptables
# The interface the default route leaves by is what "outside" means on this
# host. Derived rather than assumed: eth0 is a convention, not a guarantee.
external=$(ip -o -4 route show default | awk '{print $5; exit}')
if [ -z "$external" ]; then
  echo 'cannot determine the external interface; refusing to install a policy that would filter east-west traffic' >&2
  exit 1
fi
"$iptables" -S DOCKER-USER >/dev/null 2>&1 || exit 0
if ! "$iptables" -S ufw-user-forward >/dev/null 2>&1; then
  echo 'UFW user-forward chain is unavailable' >&2
  exit 1
fi
if "$iptables" -S ufw-docker-logging-deny >/dev/null 2>&1; then
  "$iptables" -F ufw-docker-logging-deny
else
  "$iptables" -N ufw-docker-logging-deny
fi
"$iptables" -F DOCKER-USER
"$iptables" -A DOCKER-USER -j ufw-user-forward
"$iptables" -A DOCKER-USER -p udp --sport 53 --dport 1024:65535 -j RETURN
# The edge publishes 80/443, and Docker DNATs those connections to the Caddy
# container, whose address lives inside the private ranges denied below. Without
# these three rules the deny list silently blackholes the shared edge, so a
# freshly set-up VPS answers SSH and nothing else: the site is unreachable and
# ACME can never complete its HTTP-01 or TLS-ALPN-01 challenge. Allow exactly the
# published edge ports, before the private-range denies, and nothing more.
"$iptables" -A DOCKER-USER -p tcp --dport 80 --tcp-flags FIN,SYN,RST,ACK SYN -j RETURN
"$iptables" -A DOCKER-USER -p tcp --dport 443 --tcp-flags FIN,SYN,RST,ACK SYN -j RETURN
"$iptables" -A DOCKER-USER -p udp --dport 443 -j RETURN
# DOCKER-USER governs what may enter from outside. The rules below match on
# destination alone, and DOCKER-USER is traversed by every forwarded packet —
# including the ones that never came from outside. With br_netfilter, traffic
# between two containers of the same bridge crosses FORWARD too, and it does so
# before Docker's own per-bridge ACCEPT rules. So a deny list written for
# ingress silently cut east-west traffic: an application could not reach its own
# database, a front end could not reach its API, and a container could not reach
# a service on the LAN. Nothing looked wrong — container healthchecks probe
# 127.0.0.1 inside their own namespace and never cross this chain — so the host
# reported healthy while returning 502 to every real request.
#
# Anything that did not arrive on the external interface is therefore not
# ingress, and this chain has no business filtering it.
"$iptables" -A DOCKER-USER ! -i "$external" -j RETURN
"$iptables" -A DOCKER-USER -d 10.0.0.0/8 -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 172.16.0.0/12 -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 192.168.0.0/16 -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 10.0.0.0/8 -p udp --dport 0:32767 -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 172.16.0.0/12 -p udp --dport 0:32767 -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 192.168.0.0/16 -p udp --dport 0:32767 -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -j RETURN
"$iptables" -A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix '[UFW DOCKER BLOCK] '
"$iptables" -A ufw-docker-logging-deny -j DROP
SHUTTLE_FIREWALL_LEGACY
if cmp -s "$policy" "$work/current"; then
  exit 0
fi
if ! cmp -s "$policy" "$work/legacy"; then
  echo 'managed Docker firewall script differs from the known policy; refusing automatic migration' >&2
  exit 1
fi
chmod 0755 "$work/current"
mv -f "$work/current" "$policy"
)

touch /etc/shuttle/setup.d/41-firewall-boot
fi
install -d -m 0755 /usr/local/libexec /etc/shuttle
install -o root -g root -m 0755 /tmp/shuttle-root /usr/local/libexec/shuttle-root
install -o root -g root -m 0444 /tmp/shuttle-root-trust.pem /etc/shuttle/trusted-root-operations.pem
