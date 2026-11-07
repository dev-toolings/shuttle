# Shuttle

## Installation

Sur Linux ou macOS, avec `curl`, `jq`, OpenSSL avec Ed25519 et `sha256sum` ou `shasum` :

```sh
curl -fsSL https://github.com/dev-toolings/shuttle/releases/latest/download/install.sh | sh
~/.local/bin/shuttle --help
```

Le programme vérifie la signature du manifeste et le checksum avant l'installation.
Par défaut, il installe dans `~/.local/bin`. Pour changer le préfixe, utilisez
`SHUTTLE_INSTALL_PREFIX=/chemin sh install.sh` après téléchargement du script.
Une version déjà installée plus récente est conservée. Pour autoriser une
rétrogradation, définissez `SHUTTLE_INSTALL_ALLOW_DOWNGRADE=1`. Une version
installée illisible ou de développement ne bloque pas l’installation.

Shuttle déploie une application sur un VPS unique Ubuntu 24.04 ou Debian 13.
La cible est volontairement étroite : Docker Swarm mono-nœud, Caddy partagé,
PostgreSQL natif (18 par défaut, 16 et 17 conservés pour les hôtes existants), Redis privé par application et RabbitMQ optionnel.

Shuttle applique une posture durcie vérifiable. Il ne prétend pas rendre un
serveur « 100 % sécurisé ».

## Commandes

L'interface publique contient exactement dix-sept commandes :

```text
init  infra  setup  deploy  backup  doctor  debug  helper  status  logs
secrets  skills  run  rollback  destroy  update  operations
```

Le CLI est Apache-2.0.

For an existing platform-owned Swarm, see [existing-stack deployments](docs/existing-stack.md).
After a digest-verified upgrade, `retention.keep_releases` (default 1, minimum 1)
removes superseded release tags and registry manifests only from the configured
build repositories. Live service/task images remain protected. Cleanup failures
warn without failing the upgrade; platform-owned offline registry GC reclaims
unreferenced blobs. Rollback completes inside the platform apply command before
cleanup runs.

La documentation détaillée est indexée dans [docs/README.md](docs/README.md).

## Démarrage

Préparez un VPS dédié Ubuntu 24.04 ou Debian 13, un accès console de secours,
un domaine dont les enregistrements A/AAAA pointent vers ce VPS et les ports
SSH, HTTP et HTTPS accessibles. Le poste local doit disposer de Docker avec
BuildKit pour les déploiements et d'une clé SSH dont la partie privée est
accessible via `ssh-agent` ou la configuration SSH. La capacité dépend des
services : prévoyez leur mémoire cumulée disponible pendant la promotion et
au moins 20 % d'espace disque libre.

Le fournisseur doit avoir réinitialisé le VPS et installé votre clé publique
pour `root`. Relevez ensuite l'empreinte ED25519 dans la console du fournisseur :
la clé observée au premier contact SSH ne constitue pas une preuve indépendante.

```sh
shuttle init --app demo --preset nextjs \
  --domain demo.example.com --host 203.0.113.10

# Génère ./config.json à côté des sources de l'application.
# Les valeurs de production restent sur le VPS (secrets.backend: host).
# Une fois par poste, pour tous les harness d'agents :
shuttle --install skills

# Avant le premier déploiement, faites pointer le domaine directement vers
# l'adresse IPv4/IPv6 du VPS. Caddy gère ensuite ACME automatiquement.

shuttle setup --target root@203.0.113.10 \
  --expected-host-key 'SHA256:...........................................' \
  --public-key "$HOME/.ssh/id_ed25519.pub" \
  --operator-user ops --operator-public-key "$HOME/.ssh/ops_ed25519.pub" --dry-run

# Depuis Linux, l'exécutable courant compatible avec le VPS sert de helper.
shuttle setup --target root@203.0.113.10 \
  --expected-host-key 'SHA256:...........................................' \
  --public-key "$HOME/.ssh/id_ed25519.pub" \
  --operator-user ops --operator-public-key "$HOME/.ssh/ops_ed25519.pub" --yes

shuttle doctor --strict
# Dans config.json, prévoir le délai de première émission du certificat :
# par exemple deploy.promotion_slo_seconds = 120 et un total_slo_seconds >= 120.
# Ce budget laisse 24 s à la preuve d'origine directe ; ACME peut encore échouer.
shuttle deploy
```

Lancez `init` depuis les sources de votre application. Dans un dossier vide, certains
presets, dont `node-api`, ne créent pas de `Dockerfile` : il faut en fournir un.

Lors de la création d'un Dockerfile, `shuttle init` résout les versions stables
des images de base dans leur majeure actuelle et écrit leurs digests. Si un
registre est indisponible, la génération échoue en nommant l'image concernée.
Utilisez `--image repository:tag@sha256:<digest>` pour fournir une identité
complète, avec un indicateur par image. Pour FastAPI, le tag Python doit
indiquer sa version majeure et mineure, et le tag uv doit utiliser la même
version mineure de Python. Un Dockerfile existant reste inchangé
sans `--force` ; avec `--force`, les images sont résolues à nouveau.

La première émission ACME dépend du DNS et de la validation publique. Le budget
par défaut de 30 secondes ne laisse que 6 secondes à la preuve HTTPS ; une
émission valide peut dépasser ce délai. Mesurez séparément le premier
déploiement et les suivants avant de réduire le budget. Les contrôles de
certificat et de santé restent obligatoires ([budgets](docs/configuration.md)).

Sur un hôte qu'on n'a pas le droit de toucher, `deploy.strategy: compose`
déploie sans `setup` : Shuttle construit sur votre poste, envoie les images par
SSH et lance `docker compose` avec un compte existant nommé dans la
configuration (`server.user`, `server.host_key`). Pas de helper root, pas de
Swarm, pas d'edge, et le durcissement rendu dans le fichier n'est imposé par
personne : c'est le mode de repli, documenté comme tel
([stratégies](docs/configuration.md#deploy-strategies)).

Sur un VPS neuf, le compte administrateur séparé est obligatoire : les deux
appels `setup` ci-dessus déclarent `ops` avec sa propre clé. Préparez cette clé
avant le setup (`ssh-keygen -t ed25519 -f ~/.ssh/ops_ed25519` si elle n'existe
pas), puis chargez-la dans `ssh-agent` ou déclarez-la dans la configuration SSH.
La clé doit être distincte de celle de `deploy`. Shuttle vérifie le login et
les droits administrateur avant et après la fermeture de SSH root.

**Aucun mot de passe Linux n'est généré.** Pour administrer le serveur :
`ssh ops@203.0.113.10`, puis `sudo -i`, sans mot de passe. La fin du setup
rappelle les commandes avec le port exact. `deploy` reste le compte
d'automatisation, limité au helper signé et sans accès au socket Docker.

Si d'autres personnes ont un compte sur ce serveur, nommez-les avec
`--retain-user alice` (répétable) ou `setup.retained_users` : elles gardent
leur accès SSH, leurs clés, leurs groupes et leurs règles sudo tels quels.
Tout compte non nommé perd SSH à la fin du setup. Un compte sans clé publique
est refusé avant toute modification ([détails](docs/configuration.md#accounts-that-must-survive-setup)).

Un hôte que Shuttle n'a jamais installé se prend en main avec
`--adopt --unmanaged`, en arrivant par un compte sudo existant : le plan du
`--dry-run` décrit les étapes et leurs refus avant tout `--yes`. Docker et
PostgreSQL déjà actifs gardent leur configuration ; le registre et les fichiers
Shuttle de sauvegarde et d'ordre de démarrage sont traités séparément. Le plan
indique aussi les ports publiés fermés et le conteneur arrêté par
`--cutover-edge`. Si ce conteneur appartient à un service Swarm étranger, Shuttle
refuse le basculement : supprimez ou réduisez vous-même ce service, puis relancez
setup ([détails](docs/operations.md#adopting-a-host-shuttle-never-installed)).

Une migration `--adopt` conserve l'administrateur initial s'il est distinct de
`root` et `deploy`. Depuis root, ou avec `--lock-out-first-contact-user`, il faut
fournir un opérateur de remplacement et sa clé. La console du fournisseur reste
le recours si toutes les clés sont perdues ; un mot de passe root connu n'ouvre
pas SSH root, qui reste désactivé.

Depuis Linux, `setup` peut installer l'exécutable courant comme helper. Depuis
macOS ou Windows, récupérez depuis votre compte le binaire Linux signé de la
même release (`shuttle-linux-x64` ou `shuttle-linux-arm64`), pour l'architecture du VPS. Vérifiez-le selon la procédure de
distribution, puis ajoutez `--helper-binary /chemin/absolu/du/binaire-linux`
aux deux commandes de setup. Aucun dossier `dist` préexistant n'est requis.
`doctor` exige une configuration, une identité serveur déjà attestée et le
helper installé par setup ; il ne constitue pas un audit instantané.

Une fois un helper récent installé, ses mises à jour ne nécessitent plus de
connexion root : `shuttle helper status` affiche son contrat, puis
`shuttle helper update --dry-run` et `shuttle helper update --yes` remplacent
l'exécutable par une opération Ed25519 signée. Un helper antérieur à ce contrat
doit être remplacé une dernière fois depuis la console root du fournisseur.

## Contrats de sécurité

- Premier contact SSH lié à une empreinte ED25519 obtenue hors bande.
- `deploy` n'appartient ni à `sudo`, ni au groupe `docker` et n'accède pas au
  socket Docker.
- Un compte opérateur configuré explicitement est séparé de `deploy`, se
  connecte uniquement par sa propre clé et reçoit un sudo root général. Cette
  commodité de diagnostic est une délégation root, pas un mode lecture seule.
- `shuttle debug` couvre le diagnostic Docker courant sans élargir les droits de
  `deploy` : le helper signé n'accepte que des lectures bornées aux ressources de
  l'application, et la vue `inspect` n'expose ni environnement, ni secrets,
  labels, commandes ou montages. Les logs restent toutefois le texte opaque
  produit par l'application : aucun outil ne peut y reconnaître tous les secrets.
- Les seules opérations root acceptées sont des plans Ed25519 courts et typés,
  chacun limité à ce qu'il nomme : le durcissement SSH et son retour arrière,
  l'audit, une opération applicative déclarée (migration, tâche), la
  publication des secrets, l'application d'une stack, son rollback, la
  récupération des images des releases dépassées et la mise à jour bornée du
  helper lui-même. Aucun plan ne transporte de shell.
- Le helper refuse les images non épinglées par digest, les ports applicatifs
  publics, les conteneurs privilégiés, le réseau hôte, le socket Docker et les
  montages hôte.
- PostgreSQL écoute uniquement sur loopback et `docker_gwbridge`, avec SCRAM.
- Le cluster PostgreSQL est ordonné après Docker (`32-postgres-boot-order`) : l'adresse `docker_gwbridge` n'existe qu'une fois le pont recréé, sinon la base ne répondait que sur loopback après chaque reboot.
- Redis et RabbitMQ ne publient aucun port.
- Les ports publics sont limités à HTTP/HTTPS et au port SSH configuré.
- Les mises à jour pouvant changer les dépendances (dont le noyau) sont
  appliquées; `setup` termine le reboot requis avant de fermer l’accès root.
- `setup` prouve le registre loopback, Caddy, PostgreSQL, Fail2ban, UFW et les
  unités systemd avant le durcissement SSH. La configuration SSH précédente est
  restaurée par une opération signée si l'audit post-durcissement échoue.
- `doctor` vérifie aussi les reboots requis, l’alignement Fail2ban/SSH, les
  unités systemd en échec et les exécutables SUID/SGID non gérés.

## Budgets et rétention

- `setup` : budget mesuré de 600 secondes par défaut, configurable entre 120 et
  7 200 secondes. Une convergence sûre réussit même si ce budget est dépassé ;
  le CLI signale alors le dépassement par un avertissement.
- `deploy` : budget source-vers-production mesuré, par défaut selon le framework :
  45 secondes pour Laravel et Symfony, 30 secondes pour les autres presets,
  surchargeable entre 10 et 600 secondes. Le budget est mesuré et rapporté :
  une release saine qui le dépasse reste en production et le déploiement réussit
  avec un avertissement.
- Deux releases, 5 Gio de cache registre par application, sept sauvegardes
  PostgreSQL locales et au moins 20 % d'espace libre. Avant de mesurer cet
  espace, `deploy` demande au helper de récupérer les images des releases que
  l'application a dépassées : un hôte plein de ses propres restes est nettoyé,
  pas bloqué.
- Mémoire : `deploy` refuse une promotion si la mémoire disponible de l'hôte
  (`MemAvailable`) est inférieure à la somme des limites mémoire des services
  du stack. Un rolling update start-first réclame cette marge en plus de ce qui
  tourne. Le refus nomme chaque service et sa limite ; baisser
  `services.<nom>.resources.memory` est la réponse. Par défaut 768 Mio par
  service : trois services exigent 2,25 Gio disponibles.
- Aucun `docker system prune` : seuls les artefacts possédés par Shuttle sont
  supprimés. Le helper root écrit chaque décision dans le journal de l'hôte
  (`journalctl -t shuttle-root`).

Les sauvegardes locales ne protègent pas contre la perte totale du VPS.
Le rollback restaure la stack applicative précédente, pas les données ni les
migrations de schéma. Une migration doit rester compatible avec la version
précédente ou disposer d'une restauration de données préparée et testée.
Un rolling update `start-first` dépend des healthchecks, de la capacité libre
et de la compatibilité des versions ; il ne garantit pas une disponibilité
absolue du VPS unique.

## Développement

```sh
cd app/go-cli
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/shuttle
```

Le contrat complet de configuration est décrit dans
[`docs/configuration.md`](docs/configuration.md), et l'exploitation dans
[`docs/operations.md`](docs/operations.md).

Le test d'acceptation sur un VPS fraîchement réinitialisé est automatisé par
`sh scripts/e2e-vps.sh`, avec cible, domaine et binaire fournis explicitement ;
il conserve sa configuration et ses preuves sous
`tmp/vps-e2e/`. Le premier déploiement mesure le cache froid ; le second vérifie
que le déploiement à cache chaud tient dans le budget déclaré par la
configuration générée.

Les sauvegardes applicatives chiffrées, la restauration PostgreSQL native isolée
et l’export optionnel AWS S3/Cloudflare R2 sont décrits dans
[le guide des sauvegardes](docs/backups.md). Les installations et déploiements
utilisent les dernières versions stables et leurs digests exacts. Trivy est
facultatif, via `doctor --scan-images`, et ses résultats ne bloquent pas ces
opérations ; voir [la politique des versions et CVE](docs/image-security.md).
