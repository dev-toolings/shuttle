# Documentation de Shuttle

Le point d'entrée du produit reste le [README](../README.md). Le modèle du produit se trouve dans [`adr/`](adr/0001-apache-2.0.md).

## Configurer et déployer

| Document | Sujet |
| --- | --- |
| [configuration.md](configuration.md) | Référence de `config.json` |
| [build-runners.md](build-runners.md) | Build local ou sur un runner distant |
| [existing-stack.md](existing-stack.md) | Mise à jour d'une stack Swarm gérée par la plateforme |
| [hashvault.md](hashvault.md) | Backend de secrets Hashvault |
| [image-security.md](image-security.md) | Versions stables et diagnostics de vulnérabilités optionnels |

## Exploiter

| Document | Sujet |
| --- | --- |
| [operations.md](operations.md) | Opérations durables, reprise et frontières d'exécution |
| [check-catalog.md](check-catalog.md) | Contrôles de `shuttle doctor` |
| [backups.md](backups.md) | Sauvegardes applicatives et restauration isolée |
| [backup-monitoring.md](backup-monitoring.md) | Suivi du cycle de vie des sauvegardes |
| [monitoring.md](monitoring.md) | Surveillance continue |
| [monitoring-collectors.md](monitoring-collectors.md) | Collecteurs de la surveillance |
| [monitoring-runtime.md](monitoring-runtime.md) | Garanties d'exécution de la surveillance |

## Contrats internes

| Document | Sujet |
| --- | --- |
| [operations-recovery.md](operations-recovery.md) | Réconciliateur de reprise dans `shuttle-root` |
| [helper-migration-integration.md](helper-migration-integration.md) | Migration du helper root |

## Publier

| Document | Sujet |
| --- | --- |
| [releasing.md](releasing.md) | Procédure de release |
| [release-security.md](release-security.md) | Confiance des releases et reprise des mises à jour |
