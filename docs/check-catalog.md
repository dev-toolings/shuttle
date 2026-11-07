# Catalogue `doctor`

`shuttle doctor` audite le VPS via un plan Ed25519 court et signé. L’utilisateur
`deploy` ne reçoit jamais l’accès au socket Docker. Tous les contrôles sont
exécutés sur le VPS via un plan signé et sans jeton d’infrastructure externe.

`doctor --strict` échoue dès qu’un contrôle actif est en échec ou sans preuve.

## Contrôles actifs

| Catégorie | Contrat vérifié |
| --- | --- |
| Système | Ubuntu 24.04 ou Debian 13, disque, mémoire, horloge, mises à jour, reboot requis, unités défaillantes, AppArmor, Fail2ban et désactivation LLMNR/mDNS |
| SSH | root fermé, authentification par clé, mots de passe et interaction clavier désactivés, `AllowUsers deploy` plus le compte opérateur explicitement déclaré ou préservé lors d'une adoption, drop-in signé réellement en vigueur, port effectif et jail Fail2ban alignés |
| Privilèges | `deploy` hors des groupes `sudo`/`docker`, avec son unique règle NOPASSWD limitée à `shuttle-root apply`; ce contrôle ciblé ne transforme pas le compte opérateur optionnel, explicitement root-equivalent, en anomalie `deploy` |
| Docker | service actif, registre persistant sain sur loopback, healthchecks, redémarrage, absence de socket monté et conteneurs bornés |
| Pare-feu | UFW deny-by-default, politique `DOCKER-USER`, bases non publiées et seuls SSH/HTTP/HTTPS autorisés |
| Caddy/TLS | configuration valide, API admin non publique, certificat, HSTS et endpoint de santé |
| PostgreSQL | service natif actif, écoute privée, SCRAM et sauvegarde locale récente |
| Redis | service privé et sain lorsqu’il est activé |
| Détection | échecs SSH récents agrégés, unités systemd en échec et SUID/SGID non gérés par un paquet |

## Identifiants de contrôle

Ces identifiants viennent de `app/go-cli/internal/readiness`. Ce sont les valeurs
attendues par `readiness.ignore` dans `config.json`. Selon le profil et la
configuration, un contrôle peut être sauté ou sans objet.

| Famille | Identifiants |
| --- | --- |
| `access` | `access.deploy_user_docker_group` `access.deploy_user_exists` `access.deploy_user_nopasswd` `access.deploy_user_ssh_files` |
| `adminer` | `adminer.ip_restriction_missing` |
| `caddy` | `caddy.admin_exposed` `caddy.invalid_config` `caddy.no_security_headers` `caddy.not_installed` |
| `compose` | `compose.bind_mount_sensitive_paths` `compose.env_file_missing` `compose.latest_tag_used` `compose.missing_prod_file` `compose.no_resource_limits` |
| `db` | `db.no_backup_detected` |
| `dns` | `dns.domain_not_pointing_to_server` |
| `docker` | `docker.containers_running_as_root` `docker.containers_without_healthcheck` `docker.containers_without_restart_policy` `docker.gateway_mtu` `docker.loopback_registry` `docker.no_new_privileges` `docker.not_installed` `docker.service_not_enabled` `docker.sock_exposed` |
| `filesystem` | `filesystem.unmanaged_suid_sgid` |
| `firewall` | `firewall.database_port_public` `firewall.docker_public_tcp_ports` `firewall.docker_published_sensitive_ports` `firewall.docker_user_policy` `firewall.ssh_private_interface_only` `firewall.ufw_inactive` `firewall.unexpected_public_tcp_ports` |
| `monitoring` | `monitoring.no_health_endpoint` |
| `network` | `network.link_local_name_resolution` |
| `runtime` | `runtime.database_bind_hba` `runtime.node_npm_versions` `runtime.php_fpm_service` `runtime.php_fpm_socket` `runtime.php_opcache` `runtime.postgresql_service` `runtime.redis_service` |
| `secrets` | `secrets.env_in_git` `secrets.env_world_readable` `secrets.weak_file_permissions` |
| `security` | `security.failed_ssh_logins_recent` |
| `ssh` | `ssh.allowed_users` `ssh.baseline_drop_in_effective` `ssh.configuration_valid` `ssh.keyboard_interactive_enabled` `ssh.password_auth_enabled` `ssh.port_matches_config` `ssh.root_login_enabled` |
| `system` | `system.apparmor_inactive` `system.apt_cache_stale` `system.disk_space_low` `system.fail2ban_inactive` `system.fail2ban_sshd_jail_inactive` `system.fail2ban_sshd_port` `system.failed_units` `system.memory_low` `system.os_supported` `system.other_updates_pending` `system.reboot_required` `system.security_updates_pending` `system.swap_missing` `system.time_sync_inactive` `system.unattended_security_policy` `system.unattended_upgrades_inactive` `system.updates_pending` |
| `tls` | `tls.cert_missing` `tls.hsts_missing` |

Les sauvegardes locales ne protègent pas contre la perte complète du VPS.

Les vues `shuttle debug` ne contournent pas ce contrat : elles passent par des
opérations signées en lecture seule, limitées aux ressources de l'application,
avec sorties bornées; `debug inspect` ne restitue que sa liste positive de champs
non sensibles. Les commandes Docker arbitraires restent réservées au compte
opérateur root-equivalent, lorsqu'il a été explicitement configuré.

Voir aussi [configuration](configuration.md) et [opérations](operations.md).

## Tools the checks need on the target

The DNS check runs `dig` on the target, and `setup` does not install it. Install
`dnsutils` on Debian or Ubuntu, otherwise `doctor --strict` fails that check for lack
of proof.
