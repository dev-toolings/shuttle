# DeployShuttle : regles du projet

## Versions et securite des composants

Ces regles s'appliquent aux nouvelles installations, aux configurations generees,
aux images par defaut et aux mises a jour des dependances de DeployShuttle.

- PostgreSQL est toujours installe nativement sur l'hote et gere par systemd.
  Ne jamais proposer ou installer PostgreSQL dans Docker, y compris pour une
  recette de restauration. Sa configuration doit etre adaptee a la production :
  acces prive, SCRAM, droits restreints, sauvegardes et ordre de demarrage verifie.
- PostgreSQL n'a pas de branche officiellement appelee LTS. Pour une nouvelle
  installation, utiliser la derniere majeure stable supportee et son dernier
  correctif mineur, depuis le depot officiel signe. Verifier la politique de
  support avant d'actualiser le defaut. Reference verifiee le 2026-09-13 : 18.6.
  Exclure les versions beta et RC.
- Ne pas transformer une mise a jour de configuration en migration majeure
  implicite d'une base existante. Conserver la compatibilite des sauvegardes
  et restaurer leur majeure source ; une migration majeure se prepare et se teste.
- Docker Engine, Redis, RabbitMQ, Caddy, le registre et les autres composants
  conteneurises doivent utiliser leur derniere version stable officielle,
  resolue a chaque setup et deploy. Resoudre la version puis conserver le digest exact
  dans le deploiement. Un tag mutable `latest` seul ne constitue jamais une
  identification de l'image executee.
- Les scans CVE sont des diagnostics optionnels. Ils ne bloquent ni installation,
  ni mise a jour, ni deploiement, et ne demandent pas d'exception operateur.
  Lorsqu'un scan est demande, conserver son rapport date et son identite d'image.
  Un scan absent ou echoue ne vaut pas un resultat sain. Cette decision du
  2026-09-13 remplace l'ancienne obligation de scan et de refus sur CVE.
- Conserver les images necessaires au rollback. Ne pas changer la majeure d'un
  service stateful existant sans verifier la compatibilite de ses donnees.

References :
- https://www.postgresql.org/support/versioning/
- https://docs.docker.com/scout/quickstart/

## Sauvegardes

L'export cloud est optionnel. Sans cloud, conserver une archive chiffree dans le
repertoire choisi. Les destinations cloud prises en charge sont AWS S3 et
Cloudflare R2. Les identifiants viennent de l'environnement ou du mecanisme de
credentials du SDK, jamais de config.json, des journaux ou du depot Git.
Une restauration de test doit utiliser des ressources isolees et ne doit pas
remplacer les bases, volumes, comptes ou services en production.

## Travail dans ce depot

Preserver les modifications deja presentes dans l'arbre de travail. Pour lancer
le CLI compile depuis ces sources, utiliser `make install`, jamais `shuttle update`.
Documenter les changements utilisateur en tete de CHANGELOG.md et lancer
les tests adaptes. Depuis app/go-cli, lancer gofmt -l ., go vet ./... et go test ./....
