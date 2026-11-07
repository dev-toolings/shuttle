# Shuttle: active changes

## Un nom IPv6 seul faisait échouer doctor --strict (07-11-2026)

- Cause : le contrôle DNS ne lisait que l'enregistrement A. Sur un hôte en IPv6 seul, avec un certificat Let's Encrypt valide, `doctor --strict` sortait 1 à 95 sur 100.
- Correction : sans enregistrement A, le contrôle lit l'AAAA et le compare aux adresses globales de l'hôte. Il réussit si l'adresse est la sienne et échoue sinon.
- Compatibilité : un nom avec un enregistrement A garde le même contrôle. Un nom sans A ni AAAA échoue comme avant.

## Le verrou Compose ne fonctionnait pas sur toutes les versions de mv (07-11-2026, DEV-DEPL-111)

- Cause : la publication par mv dépendait des options et du comportement de coreutils, différents sur macOS et les versions récentes de Linux.
- Correction : les métadonnées complètes sont écrites dans un fichier temporaire puis publiées par lien physique atomique. Un échec distingue un verrou existant d’une erreur de publication par la présence du fichier, sans analyser le message de ln.
- Compatibilité : les anciens verrous sous forme de dossier demandent une inspection manuelle. Aucun essai sur hôte réel n’a été effectué.

## Des exemples neutres pour la publication des sources (07-11-2026)

Les exemples et récits de diagnostic utilisent des noms et adresses de documentation afin de conserver les détails techniques sans exposer des environnements privés.

## Le plan d'adoption ne prouve plus l'accès PostgreSQL depuis les conteneurs (07-11-2026, DEV-DEPL-115)

- Correction : le plan montre une règle HBA possible et précise que seul un premier déploiement avec un healthcheck PostgreSQL peut vérifier cet accès. Un healthcheck qui ne teste pas la base ne constitue pas cette preuve.

## Le sondage d'adoption déduisait à tort les règles HBA chargées (07-11-2026, DEV-DEPL-115)

- Correction : l'adoption ne déduit plus l'accès PostgreSQL des fichiers HBA ; elle vérifie seulement que le serveur écoute sur la passerelle Docker.

## Une interruption pouvait vider la politique de rétention pendant l'adoption (07-11-2026, DEV-DEPL-115)

- Correction : après contrôle du fichier, l'adoption écrit la nouvelle politique dans le même répertoire puis la renomme ; une interruption avant le renommage conserve la politique précédente.

## Une rétention Shuttle valide ne pouvait pas être modifiée pendant l'adoption (07-11-2026, DEV-DEPL-115)

- Correction : les fichiers de rétention au format Shuttle valide sont mis à jour vers la valeur demandée entre 1 et 7 ; les fichiers étrangers et les liens restent refusés. Le plan montre l'ancienne et la nouvelle valeur.

## Une règle HBA SCRAM couvrant toutes les adresses était refusée (07-11-2026, DEV-DEPL-115)

- Correction : l'adresse HBA all couvre le réseau Docker sans masque ; samehost et samenet restent refusées si leur portée ne peut pas être prouvée.

## Les fichiers HBA inclus échappaient au contrôle du dernier chargement (07-11-2026, DEV-DEPL-115)

- Correction : l'adoption refuse les inclusions, car la date du fichier principal ne prouve pas celle des fichiers inclus ; une vérification manuelle reste nécessaire.

## Les inclusions HBA pouvaient fausser la preuve d'ordre (07-11-2026, DEV-DEPL-115)

- Correction : le sondage refuse les fichiers HBA inclus, dont les numéros de lignes ne sont pas comparables à ceux du fichier principal. Les versions sans colonne de fichier restent prises en charge.

## Le plan d'adoption omettait des étapes exécutées (07-11-2026, DEV-DEPL-115)

- Correction : le plan nomme helper-safety et l'étape administrateur lorsqu'elle est prévue, et ne classe pas le cutover demandé parmi les étapes restantes ou non tentées.

## Le plan ne nommait pas les services Swarm publiés en ingress (07-11-2026, DEV-DEPL-116)

- Correction : le sondage lit les ports publiés par chaque service et le refus de cutover nomme le service qui occupe 80 ou 443, en mode ingress ou host.

## Un refus de cutover Swarm retournait un dry run réussi (07-11-2026, DEV-DEPL-116)

- Correction : le dry run renvoie le refus de cutover ou de reconvergence avant de déclarer le précontrôle vérifié.

## Une politique de rétention étrangère pouvait être écrasée (07-11-2026, DEV-DEPL-115)

- Correction : le sondage et l'écriture refusent un fichier de rétention différent de la valeur demandée ou un lien symbolique ; un fichier identique est conservé sans réécriture.

## Une adoption interrompue après Swarm ne pouvait pas reprendre (07-11-2026, DEV-DEPL-115)

- Correction : un hôte déjà revendiqué sans checkpoint Docker peut créer le réseau overlay manquant comme étape nommée ; un réseau étranger conserve son refus.

## Un registre arrêté pouvait passer la convergence d'adoption (07-11-2026, DEV-DEPL-115)

- Correction : l'étape autonome vérifie l'appartenance du conteneur, démarre un registre Shuttle arrêté et attend sa santé et la réponse loopback avant de poursuivre.

## La preuve HBA pouvait accepter une règle masquée ou non chargée (07-11-2026, DEV-DEPL-115)

- Correction : la première règle HBA applicable à chaque base et propriétaire gérés doit autoriser SCRAM sur le sous-réseau Docker. Le sondage refuse aussi un fichier HBA plus récent que le dernier chargement PostgreSQL.

## Le basculement de l'edge acceptait une tâche Swarm étrangère (07-11-2026, DEV-DEPL-116)

- Cause : arrêter un conteneur de tâche Swarm laisse le service le remplacer et reprendre les ports 80/443 ; la restauration cible seulement l'ancien conteneur. Le test reproduit sur 46255a6 un plan qui accepte cette tâche.
- Correction : le relevé conserve le nom du service de chaque conteneur et refuse le basculement demandé avant les étapes, en dry run comme en exécution. L'opérateur doit supprimer ou réduire lui-même le service, puis relancer setup.
- Compatibilité : les conteneurs ordinaires et les exécutions sans --cutover-edge gardent leur comportement. Aucun protocole signé ni format stocké ne change. Aucun essai sur hôte réel n'a été effectué.

## Le plan d'adoption ne correspondait pas aux étapes exécutées (07-11-2026, DEV-DEPL-115)

- Cause : la présence de Docker, Swarm et PostgreSQL suffisait au sondage pour annoncer une étape ignorée, mais seuls les marqueurs de checkpoint décidaient de son exécution.
- Correction : les étapes 20-docker et 30-postgres satisfaites ne lancent plus leur corps. Le registre, le script et le timer de sauvegarde et le drop-in systemd sont nommés séparément. Le sondage refuse les prérequis réseau ou PostgreSQL manquants et les fichiers de sauvegarde étrangers ; PostgreSQL ne redémarre pas pendant cette installation.
- Compatibilité : le setup initial conserve ses commandes. Aucun protocole signé ni format stocké ne change. Aucun essai sur hôte réel n'a été effectué.

## Le diagnostic CVE pouvait scanner une autre image que celle du VPS (07-11-2026, DEV-DEPL-97)

- Cause : le diagnostic choisissait des tags locaux avant toute lecture du VPS et ignorait la selection RabbitMQ resolue. Le rapport pouvait donc porter sur une autre image.
- Correction : l'audit signe existant fournit les references retenues avec digest. Chaque image sans identite disponible utilise la selection locale et affiche sa portee ; le rapport conserve la reference, le digest et sa provenance. Une erreur de scan ne constitue pas un resultat sain.
- Compatibilite : aucun changement au protocole signe. Les scans restent optionnels et ne bloquent ni installation ni deploiement. Aucun essai sur hote reel n'a ete effectue.

## L’installation pouvait remplacer une version plus récente (07-11-2026)

- Cause : un manifeste valide pouvait désigner une release antérieure au binaire installé, sans contrôle de version.
- Correction : l’installateur refuse une rétrogradation sauf si `SHUTTLE_INSTALL_ALLOW_DOWNGRADE=1`. Une version installée illisible ou de développement ne bloque pas l’installation.
- Compatibilité : la vérification de signature et du checksum reste obligatoire, sans changement du manifeste.

## Un canal public pour les mises à jour et l’installation (07-11-2026, DEV-DEPL-10, DEV-DEPL-9)

- Cause : le site de téléchargement a fermé et le manifeste de release signé contient des assets plutôt que les URL de l’ancien site.
- Correction : le CLI utilise le dépôt public prévu et vérifie le manifeste existant ; un installateur vérifie signature et empreinte avant installation, et un export prépare les sources publiques.
- Compatibilité : le format signé et la surcharge SHUTTLE_SITE_URL restent inchangés. Le dépôt public et sa première release restent à créer.

## Les objets externes pouvaient contourner les contrôles de la stack (07-11-2026, DEV-DEPL-110, DEV-DEPL-98)

- Cause : les déclarations de volumes et secrets étaient contrôlées sans inspecter les objets Docker existants. Un volume externe pouvait monter un chemin hôte ou appartenir à une autre application.
- Correction : avant application, le helper contrôle les noms et inspecte les volumes et secrets avec les commandes Docker typées. Il refuse les volumes étrangers, les pilotes non locaux et les options de montage. Les volumes du edge et le volume de certificats adopté restent utilisables. Les nouveaux secrets Redis et RabbitMQ portent le label du propriétaire.
- Compatibilité : les secrets historiques dans l'espace de noms de l'application restent acceptés sans label ; les secrets hors de cet espace doivent porter le label de l'application. Les manifestes conservés pour rollback et reprise gardent les contrôles de leur application initiale. Le protocole signé et les formats stockés ne changent pas. Aucun essai Docker ou sur hôte réel n'a été effectué.

## Une interruption pouvait rendre un verrou Compose illisible (07-11-2026, DEV-DEPL-111)

- Cause : une interruption entre la création du verrou et son écriture empêchait la commande de reprise de lire son titulaire.
- Correction : les métadonnées sont écrites dans un dossier temporaire, puis publiées par renommage atomique sans remplacer un verrou existant.
- Compatibilité : la reprise reste manuelle et le protocole signé ne change pas. Aucun essai sur hôte réel n’a été effectué.

## Un refus local de build Compose conservait le verrou (07-11-2026, DEV-DEPL-111)

- Cause : toute erreur du build sur le serveur était considérée comme un résultat SSH inconnu, même avant le lancement de Docker.
- Correction : les refus locaux et les échecs de build dont BuildKit rapporte le code de sortie libèrent le verrou ; un échec de transport ou sans preuve de fin le conserve.
- Compatibilité : les builds Swarm et le protocole signé ne changent pas. Aucun essai sur hôte réel n’a été effectué.

## Deux déploiements Compose pouvaient supprimer une release en préparation (07-11-2026, DEV-DEPL-111)

- Cause : les promotions partagent un projet Docker et la rétention supprimait les dossiers qui ne sont ni current ni previous, y compris la préparation concurrente.
- Correction : deploy, rollback et destroy prennent un verrou par projet avant les mutations. Le verrou reste en place si une opération distante a un résultat inconnu ou si le client est interrompu ; sa suppression manuelle exige la lecture du titulaire et la confirmation de son identifiant. La rétention vérifie le titulaire et conserve les préparations plus récentes.
- Compatibilité : aucun protocole signé ne change. La reprise manuelle exige de vérifier les processus Compose sur le serveur ; aucun essai sur hôte réel n’a été effectué.

## Les images des modèles et de BuildKit restaient figées dans le CLI (07-11-2026, DEV-DEPL-96)

- Cause : les versions et digests étaient compilés dans les modèles et l'identité du builder, dont la comparaison refusait aussi un builder existant plus ancien.
- Correction : la génération résout les versions stables dans la majeure des modèles et inscrit leurs digests ; `--image` accepte une identité explicite avec digest. Un builder absent reçoit la dernière version stable de BuildKit, dont l'identité est affichée. Un builder existant conserve son image jusqu'à sa suppression et sa recréation.
- Compatibilité : sans `--force`, un Dockerfile existant reste inchangé. Aucun format de configuration ou protocole signé ne change. Aucun registre ni hôte réel n'a été interrogé pendant ces tests.

## La fermeture des writers après reboot signalait un échec malgré la reprise requise (07-11-2026, DEV-DEPL-117)

- Cause : après fermeture des writers, abort pouvait enregistrer recovery_required pour un bail ou un boot expiré puis renvoyer une erreur, affichée comme une fermeture non résolue.
- Correction : après une erreur abort, le CLI relit le statut signé et confirme la reprise requise pour la même opération avant de déclarer les writers fermés. Il conserve l'erreur abort sur stderr et rappelle que la reprise signée reste nécessaire. Une fermeture échouée, un statut actif ou illisible conserve un code de sortie non nul.
- Compatibilité : aucun changement au protocole signé, au journal ou à la forme JSON. Aucun essai sur hôte réel n'a été effectué.

## La reprise confondait le registre supprimé avec son volume homonyme (07-11-2026, DEV-DEPL-108)

- Cause : après le SIGKILL suivant docker rm dans le test VM transmis, docker inspect renvoyait le volume shuttle-registry au lieu de constater l'absence du conteneur. Le faux Docker masquait cette collision en renvoyant No such object ; corrigé, il reproduit sur 2bacbe4 le refus « registry does not mount the journaled data volume ».
- Correction : toutes les lectures du registre par nom précisent container inspect, pour l'observation de reprise, son attente de santé et les vérifications après reboot. Le test simule le volume renvoyé par l'inspection générique et No such container pour l'inspection typée ; il vérifie aussi le type de la sonde de santé après recréation.
- Compatibilité : aucun format signé, journal ou paramètre réseau ne change. Le volume et sa preuve restent conservés. Les inspections de tâches et conteneurs par ID restent inchangées ; aucun nouvel essai Docker ou sur hôte réel n'est revendiqué ici.

## La reprise des writers exige le CLI de cette release lorsque le journal porte la preuve du registre (07-11-2026, DEV-DEPL-108)

- Cause : operations writers utilise un lecteur Python administrateur embarqué dans le CLI, qui renvoie le record complet dans un snapshot record/writers. Après un déploiement interrompu portant registry_replacement, le décodeur strict de l'ancien CLI refuse le champ imbriqué avant observation ou fermeture des writers, pour --dry-run comme pour --yes. La projection des réponses du helper ne modifie pas ce lecteur déjà distribué.
- Correction : la procédure exige désormais le CLI de cette release, qui introduit la preuve DEV-DEPL-108, ou une version ultérieure pour ces deux commandes. Il faut mettre à jour le CLI exécutant la reprise, puis relire --dry-run avant confirmation ; mettre à jour uniquement le helper du VPS ne suffit pas. Le test fige la forme historique du snapshot imbriqué, démontre son refus avec la preuve et vérifie que le lecteur actuel conserve la preuve et l'inventaire.
- Compatibilité : aucun comportement, protocole ou journal n'est modifié dans ce suivi documentaire. L'ancien lecteur accepte toujours les snapshots sans cette preuve ; les réponses de statut et de contrôle restent projetées. La preuve durable doit rester dans le journal. Aucun essai SSH ou sur hôte réel n'a été effectué.

## La preuve privée du registre rendait les réponses illisibles pour un ancien CLI (07-11-2026, DEV-DEPL-108)

- Cause : le champ registry_replacement ajouté au journal était aussi sérialisé dans les réponses de contrôle et de statut. Le décodeur strict du CLI de c762f5f refusait ce champ inconnu, y compris après une fin de déploiement déjà enregistrée comme réussie. Le test reproduit les quatre refus sur renouvellement, statut actif, fin et statut terminé.
- Correction : les deux sorties projettent une copie du record sans la preuve privée. Le test utilise la forme stricte historique, compare tous les champs publics et relit le journal pour vérifier que la preuve durable reste intacte.
- Compatibilité : aucune modification du protocole signé, du format du journal ou des règles de rétrogradation. Un ancien helper refuse toujours le champ privé lorsqu'il lit directement le journal ; la sonde du candidat de c762f5f rencontre ce refus en vérifiant les inventaires de writers conservés. Les réponses de contrôle et de statut restent compatibles avec l'ancien CLI. Aucun remplacement de binaire ni essai sur hôte réel n'a été effectué.

## Un registre supprimé pendant son remplacement bloquait toute reprise (07-11-2026, DEV-DEPL-108)

- Cause : une interruption entre rm et création supprimait le conteneur dont la reprise tirait son identité. Le volume restait présent, mais la seule réparation disponible était docker start. Le test reproduit un refus même avec le bon volume et l'image locale attendue.
- Correction : avant toute mutation du registre, le helper journalise le digest issu de la demande signée et une empreinte des métadonnées stables du volume existant. La reprise confirmée recrée le registre absent seulement si le volume correspond et si l'image locale porte le digest attendu. Elle revérifie ces preuves avant action, conserve les paramètres loopback et le durcissement existants, puis vérifie la santé. Les tests couvrent le cycle du journal et de la reprise confirmée, le volume remplacé avant ou après confirmation, le mauvais digest, le daemon indisponible, le refus d'une liaison publique et l'échec d'écriture du journal avant toute destruction.
- Compatibilité : le champ registry_replacement est optionnel et omis lorsqu'il est absent ; la version du journal et le protocole signé ne changent pas. Les anciens journaux restent lisibles et continuent de refuser une recréation sans preuve. Aucun volume n'est créé volontairement ni supprimé, aucune image n'est téléchargée par la reprise. La preuve porte sur l'identité du volume, pas sur l'intégrité de chaque blob. Aucun essai Docker ou sur hôte réel n'est revendiqué.

## Deux déploiements pouvaient remplacer le registre partagé en même temps (07-11-2026, DEV-DEPL-107)

- Cause : la convergence du registre exécutait pull, stop, rm et création sans exclusion entre applications. Deux appels concurrents reproduisent deux remplacements du même digest ; un push actif ne prend pas le verrou des ressources partagées.
- Correction : l'inspection et le remplacement prennent ce verrou, puis le remplacement exige une opération seule sous le verrou du journal. Le second appel relit donc le digest courant. En présence d'une autre opération, la convergence est différée sans arrêter le registre ; le diagnostic indique la cible signée et le digest observé, conservé pour les commandes suivantes. Les tests reproduisent le double remplacement et vérifient la poursuite du déploiement après report, sans modification du manifeste signé.
- Compatibilité : le protocole signé et les journaux restent inchangés. Le digest demandé reste une cible de convergence, pas une attestation de remplacement ; le manifeste applicatif ne contient pas le service registre. Le prochain déploiement seul peut appliquer la mise à jour différée. Aucun Docker ni hôte réel n'a été utilisé pour ces vérifications.

## Le seuil disque des déploiements empêchait un rollback (07-11-2026, DEV-DEPL-109)

- Cause : le contrôle commun du helper exigeait 20 % d'espace libre même pour remettre en service la release conservée. Le test sur la base c762f5f reproduit le refus à 19 %, avant toute soumission à Docker.
- Correction : le rollback conserve une réserve de 1 % pour les écritures du journal, des manifests et des métadonnées d'exécution, sans réserver la marge d'une nouvelle release. Les tests atteignent la soumission simulée à Docker à 19 % et à 1 %, refusent à 0,99 % et vérifient que les deux contrôles du déploiement refusent toujours à 19 %.
- Compatibilité : le déploiement garde son seuil de 20 %, ses précontrôles et ses valeurs par défaut. Le helper choisit la réserve depuis l'action signée existante ; aucun protocole, format stocké ni drapeau ne change. Le contrôle porte toujours sur la racine, sans mesurer une partition Docker séparée. Aucun essai sur hôte réel n'est revendiqué.

## Un helper rétrogradé pouvait reprendre un destroy avec d'anciennes règles (05-11-2026, DEV-DEPL-102)

- Cause : les journaux portant le consentement de suppression conservaient le schéma v1 et la sonde du candidat vérifiait l'interface sans comparer les versions. Un consentement faux omis du JSON pouvait rester lisible par un ancien helper. Les refus déterministes imposaient une récupération globale, les temporaires bloquaient indéfiniment le remplacement et setup contournait le contrôle des journaux.
- Correction : les nouvelles écritures utilisent v2, refusé par les lecteurs historiques de journaux ; le helper compare sa version à celle du candidat réel. Le drapeau signé `--allow-downgrade` autorise un retour explicite, mais tout journal de destroy restant le bloque sous verrou. Les refus de version confirmés clôturent la réservation en échec sans récupération ; les sondes incertaines restent bloquantes. Setup refuse également de remplacer un helper avec un journal en attente dès une première étape dédiée, avant tout envoi de fichier, toute mutation de l'hôte et la prise en charge en mode adoption. Seuls les temporaires `.shuttle-root-<chiffres>`, réguliers, root et strictement 0600, sont ignorés sans modification. Les tests exécutent la commande réelle jusqu’au plan signé et le chemin privilégié de refus ; ils vérifient le consentement faux sans drapeau, vrai avec drapeau, la conservation de la réservation et de la récupération si une intention reste en attente, puis la réservation suivante après un refus sûr. Les mutations ciblées protègent ces connexions, le nettoyage de l’admission et le premier contrôle de setup.
- Compatibilité : v1 reste lisible sans ajouter de consentement, puis devient v2 à la prochaine écriture. Les builds `dev` et `git describe` restent installables sans journal en attente ; un helper de développement installé bloque aussi un candidat release tant que ce journal existe. Un ancien helper déjà installé et les journaux v1 non réécrits ne sont pas rétroactivement protégés ; les versions antérieures au lecteur de journaux nécessitent aussi le contrôle de rétrogradation. La procédure figure dans `docs/operations-recovery.md`. Aucun essai sur VM ni changement d'hôte réel n'est revendiqué.

## Un destroy bloquait le scan des mises à jour du helper (05-11-2026, DEV-DEPL-101)

- Cause : le scan refusait le répertoire privé `destroy-cleanup` conservé après un destroy, ainsi que les temporaires de journal laissés par une interruption.
- Correction : le scan reconnaît ce répertoire et les temporaires du journal et du writer store, avec contrôle du type, du propriétaire et des permissions ; les entrées inconnues restent refusées. Le précontrôle précède la phase de mutation et clôture une réservation sans phase en échec sans récupération ; le client demande également ce refus si nécessaire. Les tests couvrent le scan, le refus et la procédure administrateur sur fixtures.
- Compatibilité : l'ancien helper installé effectue le premier scan, donc une release corrigée ne suffit pas sur un hôte déjà bloqué. La procédure de `docs/operations-recovery.md` refuse tout journal de destroy restant et ne retire que le répertoire vide, sous verrou, avant récupération signée puis mise à jour. Aucun journal ni donnée n'est supprimé ; une phase déjà commencée conserve ses preuves et exigences de récupération. Aucune validation sur VM n'est revendiquée.

## Un échec de dump en reprise conservait les noms des bases déjà supprimées dans le ledger (05-11-2026, DEV-DEPL-70)

- Cause : après une suppression partielle, le chemin de conservation effaçait
  la preuve des objets terminés du journal sans retirer leur propriété du ledger.
  Une base recréée hors Shuttle sous le même nom pouvait donc être supprimée
  lors d’un prochain destroy explicitement autorisé.
- Correction : les suppressions confirmées sont retirées du ledger avant de
  convertir le journal en objets conservés, y compris si l’échec de dump n’a
  pas pu être enregistré. Un échec d’écriture ou de synchronisation du ledger
  conserve le journal et sa preuve ; la reprise réécrit durablement le ledger.
  Les tests permanents couvrent les trois chemins d’échec, la nouvelle base
  homonyme et les mutations qui omettent le retrait ou retirent un objet en attente.
- Compatibilité : les objets en attente, explicitement conservés et étrangers
  au plan restent dans le ledger avec leurs identifiants. Aucun nom sans preuve
  de suppression n’est retiré et aucun consentement n’est ajouté. Les essais
  sur VM et la mise à jour des helpers restent à effectuer.

## La reprise destroy pouvait appeler un helper sans garde-fous et perdre la preuve d’un drop (05-11-2026, DEV-DEPL-70)

- Cause : la reprise ne vérifiait pas le contrat du helper et assimilait un exit 1
  de PostgreSQL à un refus certain. Les générations suivantes de dumps ne
  revérifiaient pas l’espace ; leur délai fixe pouvait épuiser le watchdog.
  Un échec après suppression partielle annonçait des bases déjà supprimées comme
  conservées, masquait stderr et gardait un répertoire vide sans ledger.
- Correction : chaque plan et application de reprise destroy exige
  `destroy-safe-options`, avec indication de `shuttle helper update`. Après
  exit 1, l’OID est relu : absence confirmée, refus certain ou intention conservée.
  Chaque génération contrôle l’espace et estime son délai depuis la taille,
  dans le temps restant du watchdog avec une réserve pour le nettoyage.
  Un budget insuffisant conserve les données. Le rapport nomme seulement les
  objets encore en attente, explique l’échec et conserve le diagnostic nettoyé
  de pg_dump. Un état sans ledger est entièrement retiré. Les tests couvrent
  aussi la suppression de la base suivante après un refus certain.
- Compatibilité : aucun consentement n’est ajouté à un ancien journal ; les
  reprises des autres opérations gardent leur chemin habituel. Les archives
  existantes restent conservées. Les essais sur VM et le déploiement du helper restent à
  effectuer ; aucune connexion à un hôte réel n’a été utilisée pour ces tests.

## La reprise destroy réutilisait un dump antérieur à une intention interrompue (05-11-2026, DEV-DEPL-70)

- Cause : une intention de drop persistée avant le lancement de la commande
  autorisait la réutilisation d'une archive malgré des écritures plus récentes.
  Un drop refusé laissait aussi son intention bloquer les bases suivantes.
- Correction : chaque reprise utilise une nouvelle génération de dumps et
  conserve les anciennes archives. Le contrôle OID protège toujours les objets
  recréés. Un refus natif terminé efface son intention avant la base suivante ;
  un timeout, signal ou résultat inconnu conserve l'intention pour la reprise.
  Le test de refus suivi d'un échec de reload vérifie que la reprise garde le
  ledger et les identifiants des objets conservés, et détecte la mutation P2.
- Compatibilité : aucun consentement supplémentaire n'est déduit ; les bases
  absentes sont ignorées et les anciennes archives ne sont ni écrasées ni
  réutilisées. Les échecs certains gardent la nouvelle tentative normale.

## Destroy bloquait la nouvelle tentative après un drop refusé (05-11-2026, DEV-DEPL-70)

- Cause : un refus PostgreSQL après un dump réussi laissait le host en reprise
  obligatoire malgré le conseil de relancer destroy. La reprise réutilisait
  aussi un dump antérieur sans tentative de drop, et les lignes d'inventaire
  épuisaient la limite de 32 actions avec 11 bases et 11 rôles.
- Correction : les objets non supprimés restent dans le ledger avec leurs
  identifiants ; le nettoyage se termine avec une erreur connue qui autorise
  une nouvelle tentative normale. Une reprise prend un nouveau dump sous un
  autre nom, sauf pour la base visée par une intention de drop déjà journalisée,
  protégée par son OID. L'inventaire complet est séparé de l'unique action de
  nettoyage et reste lié à la confirmation. Le rapport d'échec garde un délai
  pour ses lectures PostgreSQL. Les tests utilisent le vrai stderr du helper
  et la clôture effective des writers ; les refus sans preuve connue sont testés.
- Compatibilité : les archives précédentes sont conservées, les erreurs autres
  qu'un refus connu restent soumises à reprise, et aucun consentement de drop
  n'est ajouté. Les contrôles et essais VM doivent utiliser le helper actualisé.

## La simulation destroy échouait sur les volumes facultatifs absents (05-11-2026, DEV-DEPL-70)

- Cause : le test réel sur VM d'une application sans Redis ni RabbitMQ a
  rencontré le message Docker `volume managed-app_redis_data not found` sur
  stderr. Le lecteur de stdout conservait seulement `exit status 1`, ce qui
  empêchait la découverte de reconnaître l'absence du volume ou d'un secret.
- Correction : les lectures de sous-processus conservent stderr dans l'erreur,
  sans le mélanger au stdout analysé. Le test exécute un vrai processus local
  reproduisant les flux Docker et couvre les volumes absents, les secrets
  absents, les avertissements et les erreurs réelles du daemon.
- Compatibilité : le destroy effectif et la découverte de reprise conservaient
  déjà stderr ; leur comportement reste inchangé. Une erreur autre que
  l'absence reste bloquante, et le code de sortie du sous-processus est conservé.

## Destroy pouvait encore supprimer les bases sans consentement ni dump (05-11-2026, DEV-DEPL-70)

- Cause : la suppression limitée au ledger était déjà livrée, mais un simple
  `destroy --yes` supprimait toujours ses bases et rôles sans sauvegarde préalable.
  La première correction conservait le ledger mais bloquait sa reprise, prenait
  le dump avant le drainage et datait le plan avant l'attente de réservation.
- Correction : les bases, rôles, identifiants et ledger restent conservés par
  défaut. Le consentement et la simulation voyagent dans le plan signé, daté
  après réservation. Avant toute mutation, le contrôle d'espace exige la taille
  des bases et une réserve de 10 %. Les dumps natifs sous l'uid `postgres` suivent
  le drainage et précèdent les drops ; seules les archives vérifiées sont
  publiées par renommage. Un échec conserve tous les objets PostgreSQL, termine
  le reste du destroy et clôture l'opération avec une erreur et la commande de
  nouvelle tentative. Le même plan signé ne peut pas rejouer cet échec connu. Un début de dump
  journalisé sans succès confirmé impose aussi la conservation, même si le
  disque empêche ensuite d’enregistrer l’échec.
  La reprise ne traite plus un ledger conservé comme du nettoyage inachevé ;
  sans journal, elle libère la réservation sans toucher l'application active.
  Son aperçu et son compte rendu nomment les objets et chemins de dump.
- Compatibilité : le client refuse les helpers sans le contrat requis. Les
  ledgers incomplets et journaux sans consentement ne déduisent aucune propriété
  du nom. Un rôle reste conservé dès qu'une base est gardée, même si cette base
  l'utilise seulement pour se connecter. Les archives finales ne sont pas
  purgées automatiquement. Compose refuse les deux options nouvelles. Les
  ledgers du parc, les scénarios VM et la politique de rétrogradation du helper
  restent à vérifier ; aucune adoption automatique n'est ajoutée.

## Redis 8 sans REDIS_VERSION bloquait les mises à jour et la récupération (05-11-2026, DEV-DEPL-100)

- Cause : les deux lecteurs exigeaient `REDIS_VERSION` dans l'environnement de l'image, alors que Redis 8 ne la déclare plus.
- Correction : lorsque cette variable manque, le helper lit la version prouvée par `redis-server --version` dans l'image exacte, sans réseau, avec système de fichiers en lecture seule, sans capacités, sous utilisateur non privilégié et avec délai borné. Une réponse non reconnue est refusée en nommant l'image ; le tag ne fournit jamais la version.
- Compatibilité : les variables existantes restent prioritaires, les contrôles de majeure et de rétrogradation restent inchangés, et la récupération ne télécharge aucune image. RabbitMQ conserve son exigence de métadonnées, faute de sonde binaire vérifiée. La recette réelle sur VM reste à effectuer.

## Swarm annonçait no-new-privileges sans l'appliquer (05-11-2026, DEV-DEPL-76)

- Cause : `docker stack deploy` ignore `security_opt`. Le helper validait seulement sa présence dans le YAML et donnait une fausse assurance de protection.
- Correction : les nouvelles installations Docker configurent le défaut `no-new-privileges` du daemon avant son premier démarrage. `doctor --strict` contrôle le réglage du daemon en cours, et le helper ne présente plus la clé YAML ignorée comme une garantie. Aucun second déploiement de service n'est ajouté.
- Compatibilité : les hôtes et fichiers de configuration existants restent inchangés, sans redémarrage implicite de Docker. Leur activation demande une maintenance et la recréation des tâches, Caddy compris. Le contrôle doctor porte sur les nouveaux conteneurs, pas sur les tâches antérieures. Les images dépendant de setuid ou de capacités de fichier doivent être testées. Le champ `NoNewPrivileges` du service peut rester faux avec ce mécanisme ; la preuve attendue en VM est `NoNewPrivs: 1` sur les processus des tâches. Compose et les protections explicites des conteneurs helper restent inchangés.

## Un rollback refusé écrasait le manifeste de la release courante (05-11-2026, DEV-DEPL-91)

- Cause : le traitement commun des échecs de `docker stack deploy` recopiait `previous.yml` sur `current.yml`, même après un rollback qui n'avait pas modifié ce fichier.
- Correction : seule une opération `stack-apply` restaure le contenu de `current.yml` capturé avant son écriture, après un refus de Docker ou une non-convergence. Un redéploiement identique ne reprend plus l’ancienne release de `previous.yml` ; le rollback d’urgence utilise aussi le contenu capturé dans un fichier temporaire indépendant, même si la restauration de `current.yml` échoue. Cette erreur reste jointe à l’échec retourné au client. Si le temporaire ne peut pas être préparé, `previous.yml` sert de repli uniquement lorsque ses octets correspondent exactement au contenu capturé. Le test de rollback vérifie désormais aussi que la release courante reste intacte après cet échec.
- Compatibilité : la restauration d'un déploiement échoué et le comportement d'un rollback réussi restent inchangés ; aucun accès à Docker réel n'est nécessaire au test.


## Un helper candidat bloqué retenait indéfiniment le verrou root (05-11-2026, DEV-DEPL-51)

- Cause : les deux sondes attendaient le candidat et ses sorties sans limite ; un enfant pouvait garder les descripteurs ouverts après la fin du candidat.
- Correction : une limite commune de 30 secondes couvre les réessais et la collecte sur le chemin réellement appelé par `helper update` ; la sonde de migration inutilisée est supprimée. Le groupe est arrêté avant de récolter le leader, sans parcourir les processus de l'hôte. Un descendant détaché qui conserve la sortie ou un arrêt non confirmé est signalé pour récupération manuelle.
- Compatibilité : une intention de migration reste intacte après un arrêt forcé : son identité ne prouve pas l'absence de mutation partielle ultérieure. Le refus distingue délai et signal, lit l’intention avant de la mentionner et renvoie à la procédure administrateur de `docs/operations-recovery.md` ; `--dry-run` ne prétend plus inspecter l’hôte. Un échec de finalisation ne prétend plus que le binaire a été remplacé. Avec une intention absente ou déjà terminée, une fois le leader récolté et les sorties fermées, l’échec avant renommage efface seulement sa réservation propre et permet la récupération signée ; toute intention reste conservée. Ces observations n’excluent pas un descendant détaché silencieux. Après contrôle administrateur, la procédure couvre aussi une réservation sans intention ou avec une intention déjà terminée, conservée intacte, uniquement si le helper installé diffère du candidat. Aucun changement de protocole ; la validation sur VM reste à effectuer.

## Un secret Swarm déclaré en environnement pouvait manquer sans explication (05-11-2026, DEV-DEPL-74)

- Cause : `expose: env` montait un fichier et renseignait `SHUTTLE_ENV_SECRETS`, mais seul l'entrypoint des presets PHP exportait sa valeur. La documentation promettait cet export pour toute image.
- Correction : le précontrôle local de Swarm avertit avant tout accès à l'hôte, nomme les secrets et services concernés et explique comment conserver ou fournir l'entrypoint, ou lire le fichier avec `expose: file`. La documentation décrit ce contrat réel. La validation partagée reste silencieuse pour Compose, où `env_file` fournit directement les variables sans entrypoint d'export.
- Compatibilité : aucun entrypoint n'est injecté, aucun secret n'est placé dans l'environnement de la stack. Une image dont le comportement ne peut pas être prouvé reste autorisée, y compris avec `--skip-build`. Les presets PHP fonctionnent sans changement et reçoivent le même rappel du contrat.

## Le rollback explicite pouvait rétrograder Redis et RabbitMQ (05-11-2026, DEV-DEPL-91)

- Cause : `stack-rollback` déployait directement `previous.yml`, sans la
  protection des données déjà appliquée au rollback d'urgence.
- Correction : les deux chemins réutilisent la même décision sur l'image live
  avant déploiement. Le rollback conserve Redis et RabbitMQ si nécessaire et
  refuse si leur image live ne peut être établie. Le test inspecte le manifeste
  réellement transmis au déploiement, sans contacter Docker.
- Compatibilité : les fichiers retenus restent inchangés par cette décision et
  gardent les contrôles de leur époque ; aucune nouvelle politique d'entrée ne
  bloque une ancienne stack. La validation sur VM reste à effectuer.

## Une commande réussie pouvait être rejouée avant clôture (05-11-2026, DEV-DEPL-92)

- Cause : après une réponse SSH perdue, le coordinateur acceptait une nouvelle
  phase `run` malgré un succès déjà journalisé dans la même opération ouverte.
- Correction : sous le verrou de mutation, toute répétition d'un `run` réussi
  est refusée explicitement avant l'exécution, même après une phase client.
  Le test reproduit deux exécutions avant correction, avec les deux verrous.
- Compatibilité : la clôture du succès reste possible ; les refus des opérations
  terminales et des échecs connus sont conservés, sans changement de protocole.

## Redéployer le même commit Compose écrasait la release de secours (05-11-2026, DEV-DEPL-93)

- Cause : le SHA servait à la fois de tag d'image et de dossier de release ; la préparation réutilisait ce dossier, puis la reprise arrêtait le projet lorsque `current` portait la version en échec.
- Correction : chaque tentative ajoute un horodatage au dossier de release, dont la création exclusive refuse tout dossier existant avant l'écriture du manifeste ou des secrets. La reprise relance la release intacte désignée par `current` sans déplacer ce lien. La tentative en échec ne peut plus porter son nom ; le chemin de reprise qui prétendait gérer cette situation a été retiré. Les tests détectent explicitement une absence de `down` au premier déploiement et un nom de tentative identique à la source. Chaque manifeste utilise des références de tentative immuables : une image inchangée conserve la référence déjà exécutée pour éviter une recréation, tandis qu’une image modifiée reçoit un nouveau tag. Les nouveaux tags sont créés sur l'hôte depuis les identifiants d'image sans dupliquer les couches ; la rétention supprime les anciens tags et garde les alias source utiles à `--skip-build`. La rotation compare la source et conserve la cible de rollback lors des redéploiements du même commit (W, X, X garde W).
- Compatibilité : les alias source restent disponibles pour `--skip-build` et Swarm reste inchangé ; les services Compose utilisent désormais les tags de tentative. Une ancienne référence source mutable est remplacée par un tag de tentative au prix d'une seule recréation par service. Si les images en cours ne peuvent pas être lues, le CLI le signale et utilise les nouveaux tags. Un premier déploiement en échec sans release saine exécute toujours `down` ; `deploy.auto_rollback: false` conserve son comportement explicite.

## Le build Compose distant ignorait le port SSH (05-11-2026, DEV-DEPL-95)

- Cause : le préflight utilisait le port configuré, mais le transport Docker et la recherche de clé OpenSSH utilisaient seulement le nom d'hôte.
- Correction : l'URI Docker et la recherche `ssh-keygen -lF` désignent le même port configuré, avec les crochets nécessaires pour IPv6 et `known_hosts`.
- Compatibilité : le port 22 conserve la forme habituelle pour les noms DNS et IPv4 ; les URI IPv6 sont correctement délimitées.

## Une stack signée pouvait atteindre l'hôte par ses sections globales (05-11-2026, DEV-DEPL-89, DEV-DEPL-90)

- Cause : le helper contrôlait les montages de chaque service, mais jamais les
  sections globales transmises à `docker stack deploy`, qui tourne en root. Un
  volume local avec `driver_opts` redonnait un bind mount, et un secret `file`
  pouvait faire lire un fichier de l'hôte. Audit de code du 04-11-2026 : aucune
  exploitation constatée, et il fallait une requête signée valide.
- Correction : une stack qui entre sur l'hôte est refusée si elle porte
  `driver_opts`, un driver de volume autre que `local`, un driver de réseau
  autre que `overlay` ou `bridge`, un `env_file`, une entrée `configs` globale
  ou un secret non `external`. Les sections globales d'un fichier compose
  traversent presque toutes le renderer sans changement : le client applique
  donc le même contrôle avant le build, `--dry-run` compris. `infra recreate`
  va plus loin avant de détruire le guest : il joue tous les contrôles locaux
  du deploy, rend la stack avec des digests factices et lui applique la
  politique du helper, car un refus après la destruction ne laisse aucune stack
  retenue. `.env` ne sert qu'à ce contrôle et ne rejoint pas l'environnement de
  `pvecli`. Un store de secrets local demande donc sa phrase de passe deux fois.
- Compatibilité : une stack sans ces formes est inchangée, et `env_file` reste
  permis dans le fichier compose, le renderer le retire. Un fichier compose
  avec un volume NFS, un driver de plugin ou macvlan, un secret `file` ou une
  entrée `configs` est refusé au prochain deploy. Les stacks déjà retenues sur l'hôte
  ne sont pas rejugées : rollback et reprise restent possibles, avec les
  contrôles de leur époque. Côté helper, le contrôle ne vaut qu'après
  `shuttle helper update`.
- Reste à faire : un `name:` de volume, ou un volume, un secret ou un réseau
  `external`, peut encore viser un objet existant d'une autre application.

## `shuttle update` réclamait un jeton que plus personne ne peut obtenir (05-11-2026)

- Cause : le site qui délivrait le jeton de téléchargement a été retiré le 14-09-2026, mais `shuttle update` refusait toujours de continuer sans lui, même avec une origine `SHUTTLE_SITE_URL` publique. La commande `shuttle license` et son paquet `internal/license` restaient aussi dans le binaire alors qu'aucune fonction n'en dépendait (`Require` n'était appelé nulle part) et qu'aucune release n'embarquait de clé.
- Correction : `shuttle update` ne présente plus aucun identifiant, la signature du manifeste reste le seul contrôle. `--token`, `SHUTTLE_DOWNLOAD_TOKEN` et `~/.shuttle/download-token` disparaissent. `shuttle license` et `internal/license` sont supprimés : l'interface publique passe à dix-sept commandes.
- Compatibilité : un script qui passe `--token` échoue sur un drapeau inconnu. Un manifeste sans URL de téléchargement est refusé sous ce nom, et non plus comme un jeton rejeté. Vérification de signature, sha256, révocation des clés et `--recover` sont inchangés.
- Reste à faire (DEV-DEPL-10) : `shuttle update` ne marche toujours pas sur nos releases. Le `latest.json` publié porte `assets`, la CLI attend `sha256` et `urls`, et rien dans le dépôt ne produit les `urls`. Mesuré à la relecture : `malformed release manifest`. L'écart existait avant ce retrait. D'ici là, `make install` et `gh release download` restent les chemins.

## Promotion Swarm plus courte et couche vendor PHP séparée (01-11-2026, DEV-DEPL-83, DEV-DEPL-85)

- Cause : la convergence recevait 55 % du SLO quelle que soit la release (web, SLO 90 s : 49,5 s, échec du 01-11 alors que la tâche était saine) ; `update_config` codait en dur `monitor: 10s` et `parallelism: 1` ; `stack-reclaim` tournait avant le build ; les Dockerfiles PHP générés copiaient vendor avec le code (couche de 117 Mo par release mesurée sur Core).
- Correction : budget Swarm à deux modes, choisi par le helper avant `docker stack deploy` (parts historiques et plancher 120 s pour une première release ou un domaine sans certificat valide ; sinon reload Caddy, preuve d'origine et disponibilité plafonnées à 10 s, convergence jusqu'à 410 s) ; `deploy.update_monitor_seconds` (5 s par défaut) et `update_parallelism` par service ; reclaim pendant un build local sans push, push après le contrôle disque ; étapes `deps` et `app-tree` dans les Dockerfiles Laravel et Symfony. Compose inchangé.
- Reste à faire avant release : e2e sur VM jetable (rollback, couche vendor en cache après une release de code, mesure de l'attente d'environ 9 s après convergence).

## La re-convergence pouvait casser les certificats de l'edge après rollback (30-10-2026)

- Cause : `setup --adopt` réattribuait les volumes Caddy à `10001:10001` avant
  la mise à jour Swarm. Sur production-host, le 30-10-2026, l'edge historique
  tourne en root avec `cap_drop: [ALL]` (lu en lecture seule) : après un
  rollback, ce root sans `DAC_OVERRIDE` n'aurait plus pu lire ses certificats
  en mode 0600, et le HTTPS de toutes les apps de l'hôte serait tombé.
- Correction : avant le changement de propriétaire, la re-convergence relève
  le propriétaire de chaque chemin des volumes gérés (pas seulement la
  racine) dans un fichier temporaire privé, et refuse de continuer si le
  relevé est illisible. La remise rend à chaque chemin son propriétaire
  exact (lignes lues entières : un nom finissant par une espace reste
  intact) ; un chemin disparu depuis le relevé est sauté sans interrompre la
  remise ; un fichier créé pendant l'essai prend le propriétaire de la racine. Après
  le retour à la spec précédente, elle restaure ces propriétaires avant les
  vérifications HTTP et HTTPS, dès que l'échec est constaté, sans attendre la
  fin du rollback Swarm (l'ancien edge ne peut pas démarrer avant). Le
  filet est armé avant le premier changement de propriétaire : toute sortie
  sans edge convergé (précontrôle, deploy refusé à spec inchangée) rend
  aussi les propriétaires. Sur un rollback explicite, les propriétaires
  reviennent avant la demande, lancée avec `docker service rollback --detach`
  pour ne pas attendre une tâche qui ne peut pas démarrer. Les volumes déjà
  en `10001:10001` sont ignorés.
- Preuve : aller-retour réel sur un volume Docker avec l'image `caddy:2`
  (racine 10001, sous-dossier 1234:5678, clé root 0600 dans un chemin avec
  espace) : propriétaires rendus à l'identique. Test du script généré avec un
  faux Docker, qui vérifie l'ordre de
  restauration avant le contrôle HTTP, l'absence de restauration après une mise
  à jour réussie et le saut des volumes déjà en `10001:10001` ; validation par
  `sh -n`.
- Budget de reprise du rollback porté de 60 à 150 s : l'e2e a vu Swarm
  démarrer la tâche de rollback exactement 60 s après sa création dans 2
  rollbacks automatiques sur 6 (relance de l'allocateur), ce qui signalait
  un CRITICAL environ 10 s avant que l'edge revienne.
- Le délai SSH de la re-convergence passe de 2 à 10 minutes : il couvre
  l'attente de la mise à jour (120 s), la reprise (150 s), le pull, le
  relevé et les sondes, sinon un rollback lent était coupé avant son
  compte rendu.
- E2E (VM jetable 246, edge réglé comme production-host) : sans correctif
  (v0.0.62), edge bloqué en `rollback_paused` 0/1 et `permission denied` sur
  les certificats ; avec rc4, retour à root, volumes et sous-chemins rendus
  à l'identique, même certificat (même numéro de série), puis adoption
  réussie en `10001:10001`.
- Compatibilite : le comportement du `setup` neuf reste inchangé ; seuls les
  rollbacks de la re-convergence en adoption restaurent les propriétaires.

## Les tests Go ne profitaient pas des 16 cœurs (30-10-2026)

- Cause : `go test ./...` prenait environ 98 s, dont 97,9 s dans
  `internal/cli` pour 1 067 tests de premier niveau sans `t.Parallel`. Trois
  tests totalisaient à eux seuls 59,9 s.
- Correction : `scripts/go-test-sharded.sh` compile une fois chaque paquet,
  distribue ses tests entre des processus concurrents et utilise les durées
  précédentes pour équilibrer les prochaines exécutions. Le nombre de
  résultats est vérifié contre la liste avant de déclarer la réussite.
- Preuve : le 30-10-2026, sur le poste (16 cœurs), `go test ./...` prend 98 s
  et `scripts/go-test-sharded.sh -j 8` 32,9 s pour 1 097 tests (3 paquets),
  avec le même décompte. Le plancher restant est le test le plus lent (30 s).
- Défaut corrigé à l'intégration : `-test.run` passait la regex en argument
  séparé, que les tests qui lisent `os.Args` prenaient pour une commande ;
  la regex est désormais passée en un seul jeton `-test.run=...`.
- Compatibilité : `make test` et les tests restent inchangés ; `make test-fast`
  ajoute le nouveau lancement parallèle.

## Docker 29 pouvait bloquer destroy et recovery (30-10-2026)

- Cause : l'e2e sur VM 246 avec Docker 29.9.2 a montré que l'inspection des
  volumes, secrets, services et réseaux absents renvoyait « <type> <nom> not
  found ». Le helper ne reconnaissait que l'ancien message « no such <type> ».
  Un destroy sans Redis, RabbitMQ ou base échouait alors en
  `recovery_required`, bloquait les déploiements de l'hôte et empêchait aussi
  `shuttle operations recover` de terminer.
- Correction : un prédicat commun reconnaît les deux formats Docker et vérifie
  le type d'objet pour écarter les autres erreurs « not found ».
- Preuve : tests ciblés pour les messages Docker 29 et historiques, les erreurs
  sans rapport et l'interdiction des comparaisons textuelles directes.
- Compatibilité : les anciens messages restent reconnus et aucune autre étape
  de suppression ou de récupération ne change.

## Destroy refusait toute stack Swarm à cause du format de la durée d'arrêt (30-10-2026)

- Cause : le helper lisait `StopGracePeriod` avec le gabarit Docker brut, qui
  rend une durée Go (`10s`), alors que son parseur n'accepte que des
  nanosecondes. `docker stack deploy` pose 10s sur chaque service : l'e2e du
  30-10-2026 (Docker 29.9.2, VM jetable) a vu `invalid Docker stop grace period
  "10s"`, un destroy en `recovery_required` et tout l'hôte bloqué.
- Correction : le helper demande `{{json ...StopGracePeriod}}` (nanosecondes,
  `null` si absent), et `null` vaut la valeur par défaut de 10 s.
- Preuve : tests du parseur (nanosecondes, `null`, refus de `10s` et d'un jeton
  inconnu) ; sortie `{{json}}` vérifiée sur la VM : `10000000000`.
- Compatibilite : actif après `shuttle helper update`.

## setup --adopt échouait sur un script Caddy laissé dans /tmp (30-10-2026)

- Cause : `setup` dépose `/tmp/shuttle-caddy-volumes.sh` en root 0600. La
  réclamation d'adoption nettoyait les autres fichiers de staging mais pas
  celui-ci : dans un `/tmp` sticky, l'utilisateur sudo de l'adoption ne pouvait
  pas le remplacer (`mv: cannot move ... Operation not permitted`, e2e du
  30-10-2026 sur VM jetable), et la re-convergence de l'edge s'arrêtait.
- Correction : le fichier est ajouté au nettoyage, et un test de contrat exige
  que chaque chemin fixe `/tmp/shuttle-*` envoyé par setup ou l'adoption y
  figure.
- Preuve : `TestAdoptionClaimRemovesEveryStagedUpload`.
- Compatibilite : aucune action requise.

## Le balayage hôte ne supprimait jamais une image tirée par Swarm (30-10-2026)

- Cause : avec le magasin d'images containerd (Docker 29), Swarm nomme une
  image tirée `busybox:1.36@sha256:...`. `docker image ls` montre le tag, mais
  `docker image rm busybox:1.36` répond « No such image » : le balayage de
  DEV-DEPL-68 gardait donc toute image tierce remplacée, en ne le notant que
  dans le journal du helper.
- Correction : quand le tag seul ne se résout pas, le balayage essaie les noms
  qualifiés par digest relevés au moment du plan, toujours sans `--force` ; un
  refus « image utilisée » n'essaie rien d'autre.
- Preuve : e2e sur VM jetable (Docker 29.9.2) qui a reproduit le défaut, test
  `TestRemoveRootHostImageRefFallsBackToPinnedDigestName`.
- Compatibilité : aucune image protégée n'entre dans le plan ; seul le nom
  employé pour la supprimer change.

## Destroy pouvait bloquer les opérations de tout l'hôte (30-10-2026)

- Cause : après `docker service rm`, Swarm pouvait encore conserver un
  conteneur de tâche arrêté qui référençait un volume. Le helper ne vérifiait
  que les conteneurs actifs, imposait un délai fixe de 30 secondes, puis
  échouait sur un volume temporairement « in use ». Le parseur ne garantissait
  pas strictement le contrat de durée d'arrêt en nanosecondes. Un arrêt au
  milieu d'un `dropdb` pouvait aussi laisser le nom en
  attente après la suppression effective, puis viser une base recréée. Les
  processus enfants PostgreSQL pouvaient survivre à l'échéance, une reprise
  pouvait redécouvrir un volume créé après son instantané, et des échecs de
  suppression PostgreSQL pouvaient être suivis d'une suppression du journal.
  Enfin, la recovery ne voyait pas les identifiants encore à nettoyer après la
  suppression de l'état ou de la route. L'opération globale `destroy` passait
  alors en `recovery_required` et bloquait l'hôte (demo-prod,
  30-10-2026 00:07 UTC).
- Correction : attendre l'absence de tous les conteneurs de la stack, retirer
  uniquement les anciennes tâches portant le label Swarm, et vérifier les
  labels de propriété avant chaque suppression de volume. La durée d'arrêt
  fournie par Docker fixe la borne au plus grand `stop_grace_period` plus
  30 secondes, plafonné à cinq minutes; les commandes de découverte, retrait,
  PostgreSQL et reload Caddy respectent l'échéance journalisée. PostgreSQL
  s'exécute dans un groupe de processus; l'annulation tue le groupe et
  `WaitDelay` borne le drainage des pipes. Avant chaque suppression PostgreSQL,
  le journal conserve le type, le nom et l'OID. Une reprise règle un objet
  absent sans le supprimer une seconde fois, et garde avec un rapport tout
  objet recréé avec un autre OID. Après préparation, la reprise traite
  uniquement les volumes encore inscrits dans le journal. Un échec laisse les
  objets pending et interdit la suppression du journal tant que toutes les
  listes et étapes ne sont pas terminées. La route n'est terminée qu'après
  synchronisation du répertoire Caddy. La recovery termine le destroy signé,
  même si les ressources visibles ont déjà disparu, ou libère sans action une
  opération dont le journal est absent et le reste vide. La preuve du plan
  confirmé lie l'inventaire et le journal à l'approbation.
- Reprise des volumes : un nom journalisé dont le volume a déjà disparu
  (Docker l'a supprimé juste avant l'interruption) ou qui appartient désormais
  à une autre app est soldé dans le journal. Avant, il restait en attente et
  bloquait la clôture du destroy pour toujours.
- Rôle PostgreSQL gardé : un rôle dont la suppression échoue parce qu'une base
  conservée en dépend est inscrit comme gardé dans le journal, sort de la
  liste en attente avec son intention de suppression, et garde ses
  identifiants. La reprise peut finir au lieu de répéter « PostgreSQL removal
  remains pending ».
- Preuve : les tests ciblés couvrent la deadline de découverte, le drainage et
  ses limites, les volumes appartenant à l'application, la conservation d'un
  volume marqué pour une autre application, la reprise des seuls volumes
  journalisés, la terminaison d'une tâche bloquée avec descendant, la
  réconciliation d'un drop interrompu par OID, la conservation du journal en
  présence d'objets pending, la synchronisation du répertoire Caddy, la reprise
  avec ou sans ressources restantes, la fermeture des writers, le refus de
  capacité et chaque type d'opération réservé par le CLI. L'e2e opérateur sur
  VM jetable reste en attente.
- Compatibilite : le correctif est actif après `shuttle helper update`. Jusque-là,
  le CLI refuse `shuttle destroy` sur cet hôte et indique la mise à jour du
  helper. Les autres opérations et le caractère global de `destroy` restent
  inchangés.

## Une premiere release en echec pouvait bloquer durablement l'application (30-10-2026)

- Cause : après une phase de secrets, un refus de préflight pouvait laisser une
  opération `deploy` en `recovery_required` sans manifeste ni service. Pour une
  première release, l'état des services seul ne distinguait pas une release
  jamais convergée d'une release convergée puis dégradée après un échec tardif.
  La suppression globale de stack pouvait aussi détruire des secrets de la
  stack, et le retrait d'une route Caddy sans synchronisation de son répertoire
  pouvait la faire réapparaître après un crash (errortrack, 30-10-2026).
- Correction : une preuve de writers fermés et un baseline sans release
  autorisent la libération sans action si aucun manifeste ni service n'existe.
  Le helper écrit `pending` avant l'application Docker et ne le remplace par
  `converged` qu'après son succès. Une suppression confirmée des services et
  réseaux étiquetés exige un journal lisible, lié au manifeste, qui indique
  `pending` ou `not-converged`. Une release convergée ou un ancien journal sans
  marqueur suit la récupération par réapplication. Un journal de suppression
  illisible bloque les mutations. Les volumes, tous les secrets et les bases
  sont conservés. Après le retrait d'une route, la recovery synchronise le
  répertoire Caddy avant de recharger Caddy et d'effacer l'indicateur de
  reprise. Les deux suppressions conservent leur preuve jusqu'au fsync réussi.
- Preuve : les tests `TestRecoveryFirstReleaseRefusedAfterSecretsPhaseIsReleased`,
  `TestRecoveryFirstReleaseWithServicesButNoManifestStaysUnresolved`,
  `TestRecoveryFirstReleaseThatNeverConvergedIsRemovedNotReplayed`,
  `TestRecoveryFirstReleasePendingAfterDockerRejectionIsRemoved`,
  `TestRecoveryFirstReleasePendingAfterHelperInterruptionIsRemoved`,
  `TestRecoveryFirstReleaseThatConvergedThenDegradedIsReapplied`,
  `TestRecoveryFirstReleaseInternalApplicationDoesNotTouchCaddy`,
  `TestRecoveryFirstReleaseDirectorySyncFailureIsRetriedAfterRestart`,
  `TestRecoveryFirstReleaseCaddyDirectorySyncFailureIsRetried`,
  `TestRecoveryFirstReleaseThatConvergedIsKept`,
  `TestRecoveryFirstReleaseUnreadableOperationJournalIsRefused`,
  `TestRecoveryFirstReleaseUnreadableRemovalJournalIsRefused`,
  `TestRecoveryFirstReleaseRemovalRefusesAChangedCurrent`,
  `TestRecoveryFirstReleaseIgnoresAnUnknownCurrent` et
  `TestRecoveryReapplyDoesNotForceUnconvergedServices` couvrent ces chemins.
- Compatibilite : le changement côté helper atteint l'hôte seulement après
  `shuttle helper update`, commande utilisable pendant `recovery_required`.

## Une redirection pouvait détourner la suppression privilégiée du registre (30-10-2026)

- Cause : les clients HTTP de l'aide root suivaient les redirections du registre
  loopback. Une réponse 307 pouvait transmettre un DELETE à une autre cible,
  puis faire compter sa réponse 202 comme une suppression réussie.
- Correction : tous les clients HTTP du registre root utilisent un constructeur
  commun qui refuse les redirections. Les réponses 3xx font échouer la lecture
  ou la suppression, et l'erreur de suppression conserve le code HTTP.
- Preuve : les tests `TestRootRegistryRedirect*` vérifient les redirections du
  DELETE, du catalogue, du HEAD et du contrôle de santé avec des serveurs
  `httptest` sur loopback. `TestRootRegistryHTTPClientsRefuseRedirects` protège
  le constructeur commun contre le retour de clients ad hoc.
- Compatibilite : après une erreur de nettoyage, la promotion réussie conserve
  son comportement de nettoyage différé. Le correctif est actif lorsque
  `/usr/local/libexec/shuttle-root` correspond à cette version, après
  `shuttle helper update`.

## Les déploiements et opérations distantes négocient leurs issues coordonnées (30-10-2026)

- Cause : `shuttle deploy` et `shuttle run` réservaient une opération avant de
  vérifier que le helper savait traiter l'audit des images d'infrastructure et
  refuser une opération terminée sans mutation. Avec un helper ancien, l'échec
  finissait en `recovery_required` sans indiquer la mise à jour nécessaire.
- Correction : négocier `infra-images-audit` et `operation-refusal` avant toute
  réservation. Un garde-fou de test exige que chaque action et mode d'audit du
  plan racine déclare une capacité ou appartienne à la base coordonnée v0.0.20.
- Preuve : des tests ciblés vérifient les capacités deploy/run, le message pour
  un helper v0.0.47, la compatibilité du helper courant et la couverture des
  actions et modes d'audit.
- Compatibilite : chaque hôte dont le helper est en v0.0.60 ou antérieur doit
  exécuter une fois `shuttle helper update` avant `shuttle deploy` ou
  `shuttle run`, même si son helper accepte déjà l'audit et le refus. Cette
  commande reste utilisable si une opération est déjà `recovery_required`. Le
  rollback, les sauvegardes, destroy et la synchronisation des secrets ne sont
  pas modifiés par cette exigence.

## Les commandes de reprise perdaient la configuration de la cible (30-10-2026)

- Cause : les erreurs de reprise etaient construites loin des commandes Cobra
  et ne conservaient ni le chemin `--config` ni la surcharge `-e` de l'invocation.
  Sur un depot avec plusieurs cibles, la commande copiee pouvait donc lire une
  autre configuration.
- Correction : enregistrer une fois les seuls drapeaux config et env explicitement
  modifies dans le `PersistentPreRun` racine, puis les ajouter a chaque commande
  de reprise. Les valeurs necessitant une protection shell sont echappees.
- Preuve : les tests cibles couvrent les formes sans drapeau et avec drapeaux,
  l'echappement shell, les erreurs d'execution et le refus de reprise automatique.
- Compatibilite : sans `--config` ni `-e`, les messages gardent leur texte actuel.
  Les commandes imprimees utilisent toujours `-e`, quelle que soit la forme
  utilisee dans l'invocation.

## Les incidents de commande masquaient leur cause (30-10-2026)

- Cause : les commandes de surveillance conservaient l'erreur du processus,
  mais leurs résumés fixes l'abandonnaient. Pour UFW en production, l'incident
  disait seulement que la posture ne pouvait pas être inspectée, alors que
  stderr indiquait un système de fichiers en lecture seule sur `/run/ufw.lock`.
- Correction : ajouter au résumé et aux preuves `command_error` un extrait
  borné, nettoyé et expurgé des secrets de l'erreur de commande. Les états et
  les chemins sains restent identiques.
- Preuve : les tests couvrent le cas UFW, l'extraction stderr, le nettoyage et
  l'expurgation, ainsi que Docker, le registre, PostgreSQL, sshd et fail2ban.
- Compatibilite : les contrôles fondés sur readiness restent sans détail ; leur
  traitement est un suivi séparé.

## Une réservation restait bloquée après la perte de sa réponse SSH (30-10-2026)

- Cause : le CLI créait un nouvel ID à chaque tentative. Si le helper avait
  écrit la réservation avant une coupure SSH, le CLI abandonnait sans connaître
  son ID. La réservation active bloquait les opérations incompatibles pendant
  son bail de 35 minutes, puis exigeait une récupération.
- Correction : le CLI réutilise un seul ID et renvoie le plan signé jusqu'à
  trois fois quand la commande distante a pu démarrer sans retour de statut.
  Si le résultat reste inconnu, l'erreur donne l'ID et les commandes de contrôle
  et de récupération. Le helper reconnaît sous verrou une phase
  `writers-initialize` terminée et la considère réussie sans nouvelle phase ni
  nouvelle observation de la baseline.
- Preuve : les tests ciblés couvrent la perte de réponse, la réutilisation de
  l'ID après refus temporaire, les refus définitifs, l'indication de récupération
  et l'initialisation unique des writers.
- Compatibilité : la partie CLI fonctionne avec tout helper. Avec un ancien
  helper, une réponse perdue peut rejouer l'initialisation, que le stockage des
  writers rend idempotente pour la même baseline. En cas d'erreur, le CLI nomme
  l'ID et la commande de récupération. L'évitement de la phase et de
  l'observation dupliquées est actif une fois
  `/usr/local/libexec/shuttle-root` remplacé par cette version. Aucun contrôle
  de capacité n'est ajouté.

## L'historique Swarm arrêté gardait des manifestes de versions supprimées (30-10-2026)

- Cause : les conteneurs d'historique arrêtés empêchaient la suppression de leur
  image hôte et conservaient aussi leur manifeste dans le registre.
- Correction : le manifeste registre d'une ancienne version référencée uniquement
  par un conteneur d'historique Swarm arrêté est maintenant supprimé, tandis que
  son image reste sur l'hôte. Parmi les instantanés d'état actif, seul l'échec
  du premier arrête le dépôt. Un échec de relecture est associé à sa balise,
  puis la suivante tente un nouvel instantané. Les étapes avec un résultat
  enregistré ne sont pas comptées comme non tentées. Une erreur HEAD bloque
  seulement la balise illisible, sauf si la protection dépend d'un alias
  conservé ou actif. L'échec d'inventaire des images hôte est signalé une seule
  fois au niveau du dépôt, même sans ancienne balise, et laisse continuer
  l'évaluation indépendante du registre. HTTP 405 suspend les suppressions
  registre suivantes du dépôt. Le résumé compte aussi les erreurs de dépôt et
  les étapes non tentées.
- Preuve : les tests ciblés vérifient la séparation des références actives et
  arrêtées, la reprise après deux échecs d'instantané, le décompte des seules
  étapes non tentées, l'isolation d'une erreur HEAD, le signalement d'un
  inventaire hôte en échec sans ancienne balise et la poursuite du registre.
- Compatibilité : les dépôts exacts du plan restent seuls éligibles, et les
  manifestes utilisés par un service, une tâche ou un conteneur actif sont
  conservés. Une image hôte référencée par un conteneur d'historique arrêté reste
  sur l'hôte.

## Le pré-déploiement ne réclamait que les images publiées par Shuttle (30-10-2026)

- Cause : le refus de disque mesurait tout le système de fichiers racine, mais
  le nettoyage avant déploiement ne voyait que les images du registre local et
  celles de l'infrastructure Shuttle. Les anciennes images des autres services
  Swarm et leurs conteneurs de tâches arrêtées restaient sur le disque.
- Correction : le pré-déploiement retire les conteneurs de tâches arrêtées
  seulement si une tâche plus récente du même service et du même slot répliqué
  tourne sur cet hôte. Pour un service global, cette tâche plus récente doit
  tourner sur le même nœud. Si le slot ou l'ordre des tâches est illisible, le
  conteneur reste intact. La passe retire ensuite les images réellement
  pendantes et les anciennes références de dépôts utilisés par un service Swarm
  actuel, âgées de plus de 24 heures et sans conteneur ni référence de rollback
  ou de service.
  Les références avec digest seul suivent aussi l'éligibilité de leur dépôt.
  Chaque suppression est affichée à l'opérateur.
- Protection : aucune image utilisée par un conteneur, une pile retenue ou une
  spécification Swarm actuelle ou précédente n'est supprimée. La passe hôte
  laisse les images du registre local à la passe de release. Une spécification
  précédente protège ses images de rollback sans rendre son ancien dépôt
  éligible. Les images de moins de 24 heures et les dépôts qu'aucun service
  actuel n'utilise restent intacts. La lecture d'un ensemble d'infrastructure
  retenu vide est valide pour la passe hôte quand les références Swarm assurent
  la protection; le balayage infrastructure seul continue de la refuser. Les
  commandes n'emploient jamais `--force` et ne touchent ni volumes, ni réseaux,
  ni cache de build.
- Preuve : tests de régression pour le changement de dépôt A vers B, le dépôt
  digest-only inutilisé et la passe hôte avec lecteur réel et ensemble retenu
  vide. Les tests de conteneurs couvrent les slots différents ou illisibles et
  une tâche active plus ancienne.
- Compatibilité : cette passe s'active sur un hôte après `shuttle helper update`.
  Les erreurs de nettoyage restent des avertissements et ne bloquent pas le
  déploiement. Les autres dépôts inutilisés seront traités par la tranche
  `doctor --disk` après consentement explicite.

## L'adoption corrige le Caddy partagé hérité (30-10-2026)

- Cause : `setup --adopt` considérait le service Caddy présent comme déjà
  convergé, même lorsque son conteneur tournait en root avec un système de
  fichiers inscriptible et une ancienne image. De plus, le contrôle exigeait
  `NoNewPrivileges` après `docker stack deploy`, alors que la conversion Swarm
  de Docker ne renseigne pas ce champ. La récupération TLS sur l'adresse IP
  pouvait aussi échouer malgré un domaine rétabli, et l'inventaire ne lisait
  qu'un répertoire fixe de fragments. Une mise à jour pouvait être annoncée
  réussie sans vérifier HTTP sur le port 80, une erreur de `docker stack deploy`
  pouvait quitter sans examiner le service, et le contrôle HTTPS en direct
  arrivait après des écritures sur l'hôte.
- Correction : le plan compare l'utilisateur, le système de fichiers en lecture
  seule, les capacités, l'image et les sources de volumes `/data` et `/config`.
  Les sources inattendues sont refusées avant mutation. `NoNewPrivileges` est
  retiré de la détection de dérive et des contrôles après mise à jour, car cette
  voie Swarm ne peut pas l'appliquer. Les domaines sont dérivés de la
  configuration Caddy effective, imports développés par `caddy adapt` inclus.
  Avant toute écriture sur l'hôte, un domaine HTTPS doit répondre et les
  domaines qui réussissent ce contrôle forment la référence conservée pendant
  toute l'adoption. Après les étapes hôte, chacun doit encore répondre avant
  le remplacement de l'edge; une perte entraîne un refus sans remplacement.
  Une erreur de déploiement inspecte le service: si son spec n'a pas changé,
  l'erreur est rendue sans rollback; si le spec a changé ou ne peut être lu, la
  reprise est engagée.
  Après remplacement, HTTP sur 80 et HTTPS sur 443 pour chaque domaine de cette
  référence initiale doivent réussir dans un délai borné. Tout échec passe par
  le rollback, annoncé comme rétabli seulement après les mêmes contrôles de
  trafic; sinon l'échec de récupération est explicite.
- Preuve : tests ciblés du programme shell avec des retours Docker et curl simulés.
  Ils couvrent deux domaines initialement sains dont un cesse de répondre après
  les étapes hôte, HTTPS fonctionnel avec HTTP 80 en échec, un déploiement non nul
  après modification du service, un déploiement non nul sans modification, le
  refus HTTPS avant écriture, la récupération des ports et domaines, le refus
  d'un volume de certificats non déclaré, la dérive limitée aux capacités et
  les contrôles postérieurs de toutes les propriétés de durcissement.
- Compatibilité : les hôtes existants se corrigent avec
  `shuttle setup --adopt --dry-run`, puis `shuttle setup --adopt --yes`.
  `caddy.data_volume` doit correspondre au volume de certificats existant si
  son nom n'est pas celui par défaut. La commande refuse aussi une dérive si la
  configuration effective ne fournit aucun domaine vérifiable ou si aucun
  domaine ne répond avant les changements sur l'hôte. La vérification postérieure
  couvre l'utilisateur, l'image, le système de fichiers en lecture seule et les
  capacités; `NoNewPrivileges` reste hors de portée de cette voie Swarm. Pendant
  les quelques secondes de mise à jour stop-first, l'edge est indisponible sur
  les ports 80/443.

## Les services Swarm restaient arrêtés après un reboot (30-10-2026)

- Cause : `on-failure` ne relançait pas une tâche arrêtée proprement par SIGTERM
  pendant l'arrêt de l'hôte. La limite de trois essais pouvait aussi être
  atteinte avant que PostgreSQL natif ou Redis soit prêt au démarrage.
- Correction : les services applicatifs et les services Redis et RabbitMQ
  activés utilisent maintenant `condition: any`, un délai de 5 s et
  `max_attempts: 0`. Les tâches de type job conservent `on-failure`.
- Preuve : le test `TestSwarmRestartPolicy` vérifie les services applicatifs,
  Redis, RabbitMQ et l'exception des jobs.
- Compatibilite : cette politique atteint un hôte existant au prochain déploiement
  de chaque application. Avant cela, après un reboot, relancer une application
  restée à 0/1 avec
  `sudo -n docker service update --force <app>_<service>`.

## Destroy supprimait une base PostgreSQL que Shuttle n'avait pas creee (30-10-2026)

- Cause : `shuttle destroy` ajoutait toujours le nom PostgreSQL derive de
  l'application aux bases et roles a supprimer. Pour `demo-agent`, cela a
  supprime `demo_agent`, une base de production creee par Ansible. Les objets
  crees par Shuttle avant le registre ne prouvaient pas davantage que ce nom
  appartenait a l'application.
- Correction : seuls les objets du registre de l'application peuvent etre
  supprimes. Un objet derive existant mais non inscrit est conserve et signale,
  et les identifiants revendiques par une autre application restent intacts.
  Un role conserve garde aussi son Secret Docker et son fichier de mot de passe.
  Un echec de suppression reste inscrit pour qu'un second `shuttle destroy`
  puisse reessayer. Les deploys geres refusent aussi de modifier un role ou une
  base derivee existante sans entree de registre, sans adoption automatique.
- Les identifiants des roles dont la suppression est reessayable restent
  disponibles jusqu'au prochain `shuttle destroy`, y compris pour le role derive.
- Le preflight de `stack-apply` refuse un role ou une base derivee non inscrits
  avant toute creation de volume ou de Secret d'infrastructure.
- Les sauvegardes pre-run et le cycle de sauvegarde exigent aussi la capacite
  `destroy-ledger-only` pour une application avec base geree.
- Preuve : les tests cibles couvrent les sondes d'existence, la decision de
  provisionnement, les suppressions reessayables, la conservation des secrets,
  l'ordre durable du nettoyage et le refus d'un ancien helper.
- Compatibilite : la correction est active lorsque
  `/usr/local/libexec/shuttle-root` correspond a cette version, installee par
  `shuttle setup`, `shuttle setup --adopt` ou `shuttle helper update`. Avant cela, le CLI
  refuse `destroy` et les deploys avec base geree sur cet hote. Un objet cree
  par Shuttle avant le registre doit etre ajoute manuellement a
  `/var/lib/shuttle/apps/<app>/postgres.json` avant le prochain deploy.

## La valeur `postgres_backups` etait validee mais sans effet (30-10-2026)

- Cause : la validation imposait 7, mais le script de sauvegarde supprimait
  toujours les archives au-dela de 7 sans lire cette configuration.
- Correction : accepter 1 a 7, avec 7 par defaut, puis ecrire la valeur de
  chaque application dans un fichier root prive. Le script garde le plus grand
  nombre declare sur l'hote et ignore les fichiers mal formes avec un message.
  La migration remplace les deux scripts distribues connus et refuse toujours
  une politique modifiee localement. Script et valeur sont appliques a chaque
  `shuttle setup`, hors des etapes executees une seule fois : un hote deja
  installe (marqueur `31-postgres-backup` present) les recoit au prochain
  setup, et un changement de `postgres_backups` prend effet de la meme facon.
- Preuve : les tests cibles couvrent les bornes de configuration, la retention
  executee sur de fausses archives et la migration des politiques distribuees.
- Compatibilite : l'omission ou la valeur 0 conserve le defaut historique de 7;
  `min_free_percent` reste fixe a 20.

## Les tailles de tmpfs declarees etaient remplacees par 64 Mio (29-10-2026)

- Cause : la normalisation securisee supprimait les options de chaque chemin,
  puis fixait tous les montages a 64 Mio, y compris `/tmp:size=256M`.
  Chromium pouvait remplir ce volume avec ses fichiers de memoire partagee
  et bloquer ses appels CDP sans OOM du conteneur.
- Correction : conserver `size` en octets ou unites binaires, refuser les valeurs
  invalides et les declarations contradictoires. La limite reste celle du helper
  existant : 512 Mio. Aucun changement du helper distant n'est necessaire.
- Preuve : le test de normalisation complet reproduit le remplacement avant
  correction et conserve ensuite 256/128 Mio et le defaut de 64 Mio. Les tailles
  invalides sont refusees. `make test` et `make ci` passent (tests, race,
  analyse des vulnerabilites, contrats shell, vet Linux et cible macOS).
  La revue independante donne GO sans P0/P1/P2. Residuel P3 : le plafond
  de 512 Mio reste declare separement dans le client et le helper existant.
- Compatibilite : sans taille explicite, les montages conservent le defaut de
  64 Mio. Le systeme de fichiers reste en lecture seule, avec les memes limites
  de chemins et de privileges.

## Index par version (v0.0.40 a v0.0.59)

Chaque entree ci-dessous est rangee sous la premiere release publiee qui la
contient, calculee depuis git. Les tags v0.0.43 a v0.0.46 et v0.0.57 n'ont
pas de GitHub Release: leur contenu est range sous la release publiee suivante.

- **v0.0.59**, 28-10-2026
  - Les releases se publient depuis la machine du mainteneur jusqu'en novembre
  - Le dry run adoption signalait le registre local comme port a ouvrir
  - Setup avec --adopt ignorait les cles SSH declarees sous Match
  - setup --adopt refusait l'edge Caddy des generations precedentes
  - Doctor signalait une base privee comme publique a cause des regles reject
- **v0.0.58**, 28-10-2026
  - La release v0.0.57 ne compilait pas pour macOS
  - Le registre et RabbitMQ echouaient juste apres un deploy sain
  - Setup pouvait echouer en plein durcissement SSH, ou sur un verrou apt
  - Les digests infra stales polluaient setup et deploy, le premier deploy signalait un faux retard
  - `doctor --strict` refusait les applications internes et les hotes Ubuntu ne suivaient pas la politique annoncee
  - Reexecuter setup sur un VPS Shuttle donnait un refus SSH opaque et un faux cutover
  - L'installation du monitoring activait un webhook absent et omettait l'operateur SSH
  - La creation d'une sauvegarde echouait sur un hote correctement configure
  - Le premier deploy sur un hote neuf annoncait un nettoyage reporte
  - Le monitoring alertait pendant un deploy, et ses alertes Discord etaient illisibles
- **v0.0.57**, 28-10-2026, sans GitHub Release: contenu livre par la suivante
- **v0.0.56**, 28-10-2026
  - Les anciennes images Redis, RabbitMQ et Caddy s'accumulaient sur le noeud
  - Un deploy lent ne disait pas pourquoi
- **v0.0.55**, 28-10-2026
  - Le balayage de la registry loopback pouvait supprimer les manifestes d'une autre application
- **v0.0.54**, 28-10-2026
  - Un deploy de code seul passait 70 secondes a recharger une image deja publiee
- **v0.0.53**, 27-10-2026
  - Le check security.ufw du monitoring etait toujours `unavailable` sous le timer
- **v0.0.52**, 27-10-2026
  - Le balayage des images du noeud ne liberait presque rien
  - Les alertes du monitoring echouaient en silence sur un webhook Discord ou Slack
- **v0.0.51**, 27-10-2026
  - Un deploy rate apres un rollback d'urgence affichait trois erreurs trompeuses et jamais la commande de recovery
  - Un helper update rate cachait la vraie cause derriere un message generique
- **v0.0.50**, 27-10-2026
  - Setup tuait un sshd orphelin sans le dire quand il reussissait
  - Le rollback d'urgence d'un deploy rate pouvait retrograder Redis ou RabbitMQ
  - Le helper ne synchronisait pas le repertoire apres avoir remplace current.yml ou previous.yml
  - setup echouait sur une Ubuntu 24.04 neuve quand un sshd orphelin tenait le port 22
- **v0.0.49**, 27-10-2026
  - La recovery laissait current.yml epingler une ancienne image Redis
  - Un echec avant promotion bloquait durablement le deploiement
  - RabbitMQ ne demarrait jamais avec le secret de mot de passe genere
- **v0.0.48**, 27-10-2026
  - La recovery pouvait downgrader Redis sur ses donnees persistantes
  - Un run en echec pouvait bloquer toutes les operations de son application
  - Une migration PostgreSQL pouvait demarrer sans sauvegarde recente
  - `shuttle init` ne pouvait pas generer une application interne
  - Les pins d'infrastructure redevenaient obsoletes
  - `shuttle init` generait encore Caddy 2.10.2
- **v0.0.47**, 24-10-2026
  - Un Redis retenu ne pouvait recevoir aucun correctif de securite
  - Un deploiement env-only ou secret-only annule pouvait etre annonce comme reussi
  - Les jobs CI etaient ignores depuis une branche de fonctionnalite
  - Les deploiements peuvent preparer leurs secrets avec Hashvault
  - `shuttle logs` lit chaque tache separement
  - Un deploiement annule par la sonde de disponibilite se recupere
- **v0.0.46**, 22-10-2026, sans GitHub Release: contenu livre par la suivante
- **v0.0.45**, 19-10-2026, sans GitHub Release: contenu livre par la suivante
- **v0.0.44**, 19-10-2026, sans GitHub Release: contenu livre par la suivante
- **v0.0.43**, 19-10-2026, sans GitHub Release: contenu livre par la suivante
- **v0.0.42**, 19-10-2026
  - Les gros volumes de logs finissaient en timeout SSH opaque
- **v0.0.41**, 19-10-2026
  - Un dockerfile relatif se lit depuis son contexte de build
  - make install ne garde plus de shuttle.previous
  - existing-stack : deploiement plus rapide et sans coupure inutile
  - Les anciennes releases existing-stack remplissaient le disque
  - Mettre a jour une stack existante sans remplacer son architecture
- **v0.0.40**, 15-10-2026
  - Une PWA derriere `basic_auth` ne redemande plus le mot de passe en boucle
- **prochaine release**
  - La CI et la release reviennent sur les runners GitHub

## Les releases se publient depuis la machine du mainteneur jusqu'en novembre

Le 28-10-2026, GitHub a refuse de lancer le job de release de v0.0.59
(`recent account payments have failed or your spending limit needs to be
increased`), et les runners self-hosted avaient ete retires le meme jour: le tag
etait pousse, mais aucun binaire n'etait publie. `scripts/release-publish-local.sh
<tag>` refait ici ce que fait le workflow apres son gate: build signe des quatre
cibles, verification des checksums, de la version et de la signature de
`latest.json`, puis la GitHub Release. Il refuse un arbre sale, un tag non pousse,
une release existante ou une cle de signature hors mode 0600. `release-verify`
lit aussi la table `assets` que `build-go.sh` ecrit dans `latest.json`: il
rejetait jusque-la tous les manifestes publies. v0.0.59 a ete publiee ainsi. Les
binaires et leur verification sont identiques a ceux du workflow; le script
disparait quand les minutes hebergees reviennent.

## La CI et la release reviennent sur les runners GitHub

Le runner self-hosted du VPS est retire. La variable `CI_RUNNER` n'existe plus:
la CI et la release tournent de nouveau sur `ubuntu-latest`, et le job macOS
reprend dans la matrice. Les contournements propres a ce runner (ripgrep sans
sudo, `gh` telecharge quand il manque, `sudo -n` du shim ci-local) sont retires.

## Le dry run adoption signalait le registre local comme port a ouvrir

Le 28-10-2026, `shuttle setup --adopt --dry-run` sur production-host a annonce le
port 5000 parmi ceux que `40-runtime` fermerait. Ce port etait celui du registre
Shuttle, publie en `127.0.0.1:5000->5000/tcp`; le conseil de l'ajouter a
`access.allowed_public_tcp_ports` aurait ouvert le registre dans UFW. Le survey
perdait l'adresse de bind et ne gardait que le port. Il rapporte maintenant
l'adresse avec le port et ignore les binds loopback IPv4 et IPv6, tandis que les
binds non loopback restent signales. Les anciennes lignes
`published-port=<n>` restent acceptees pour compatibilite.

## Setup avec --adopt ignorait les cles SSH declarees sous Match

Le 28-10-2026, `setup --adopt --target ops@198.51.100.30` echouait avec
`ssh: unable to authenticate, attempted methods [none publickey]`, alors que
`ssh -G ops@198.51.100.30` selectionnait `~/.ssh/id_ed25519_demo_ops`. Le
parseur conservait l'etat du bloc `Host` precedent et ignorait `Match`, donc la
cle et `IdentitiesOnly yes` n'etaient pas appliques. Les criteres `all`, `host`,
`originalhost` et `user` sont maintenant evalues ensemble. Un critere inconnu
ferme le bloc pour eviter qu'une cle de ce bloc soit utilisee par un autre hote.
Les blocs `Host`, la premiere valeur obtenue et l'accumulation des `IdentityFile`
gardent leur comportement existant.

## setup --adopt refusait l'edge Caddy des generations precedentes

Le 28-10-2026, `setup --adopt --yes` sur production-host prod s'est arrete sur
`setup found caddy running as "caddy@sha256:504a44d7...", which is not an
official image pinned by digest`. Les generations avant v0.0.58 deployaient
l'edge partage sous cette forme digest seul, la meme que `init` ecrivait dans
les configs et que la resolution traitait deja comme non renseignee. C'est
l'image officielle par digest: elle ne porte simplement pas de majeure, donc la
majeure par defaut (Caddy 2, la seule) s'applique, a la sonde de setup comme a
la lecture des images retenues au deploy. Redis et RabbitMQ sous cette forme
restent refuses: leur majeure en service protege leurs donnees.

## Doctor signalait une base privee comme publique a cause des regles reject

Le 28-10-2026, `doctor --strict` sur demo a classe
`runtime.database_bind_hba` en echec alors que PostgreSQL n'ecoutait que sur
127.0.0.1 et le pont Docker, en scram-sha-256. Les seules regles signalees
etaient les regles de fermeture standard `host 0.0.0.0/0 reject`,
`host ::/0 reject` et `local reject`: le controle traitait toute regle hors
peer ou scram comme permissive, y compris celles qui refusent la connexion.
Une regle reject ne peut jamais ouvrir l'acces, donc elle est ignoree. Une
regle publique en scram-sha-256 et une ligne en erreur restent des violations.

## La release v0.0.57 ne compilait pas pour macOS

Le workflow de release de v0.0.57 a echoue a la compilation croisee darwin:
`internal/cli/root_helper.go:345: undefined: rootStackFirstRelease`. La
variable etait declaree seulement dans un fichier `_linux.go` mais lue par du
code commun, et un test commun appelait une fonction propre a Linux. La CI des
pull requests ne compile que pour Linux depuis la pause du job macOS
(DEV-DEPL-38), donc rien ne l'a vu avant le tag. La variable vit maintenant
dans le fichier commun, le test est passe en `_linux_test.go`, et la CI vet
desormais chaque cible de release (darwin amd64 et arm64, linux arm64). Aucun
binaire v0.0.57 n'a ete publie; v0.0.58 est la premiere release du lot.

## Le registre et RabbitMQ echouaient juste apres un deploy sain

Le 28-10-2026, la recette VM sur Ubuntu 24.04 et Debian 13 a montre que le
collecteur annoncait le registre redemarre avant son etat `healthy` et sa
reponse HTTP sur `127.0.0.1:5000/v2/`. `doctor --strict` echouait alors, puis
reussissait quelques secondes plus tard. Le helper attend maintenant les deux
preuves pendant au plus 30 s et signale une panne de redemarrage si elles
n'arrivent pas.

Sur le premier deploy, le pull froid laissait RabbitMQ en `Starting` apres le
wait de convergence planifie de 16,5 s. Comme le SLO total ne s'evalue pas pour
une premiere release, le helper donne a sa convergence un plancher de 120 s.
Le plafond SSH couvre ce wait, les autres attentes et la marge; les releases
suivantes conservent exactement leur wait planifie. Aucun champ du plan signe
ne change.

## Setup pouvait echouer en plein durcissement SSH, ou sur un verrou apt

Sur l'e2e du 28-10-2026 (VM Debian 13 neuve), setup a echoue avec
`post-hardening signed audit failed: dial tcp 198.51.100.32:22: connect:
connection refused; CRITICAL: automatic SSH root rollback failed`, alors que
l'hote etait correctement durci: sshd avait pris un SIGHUP dans la seconde
meme ou setup envoyait l'audit (DEV-DEPL-64, cause enfin prouvee par le
journal sshd). La connexion qui suit le durcissement, l'audit et le rollback
retentent maintenant, pendant 30 s au plus, uniquement sur `connect:
connection refused`: une connexion refusee prouve que rien n'a tourne, donc
l'enveloppe signee n'a pas ete consommee. Toute autre erreur reste immediate.

Sur Ubuntu 24.04 neuve, setup coupait SSH dans 5 essais sur 7 (cause
mesuree le 28-10-2026): au premier boot, needrestart redemarre ssh.service
pendant les mises a jour apt de cloud-init. Quand setup arretait ensuite
`ssh.socket`, l'unite passait inactive mais systemd gardait son `MainPID`, qui
designait encore ce sshd toujours accroche au port 22. Le nettoyage des
listeners orphelins epargnait le `MainPID`, le redemarrage ne pouvait pas se
lier au port, systemd supprimait `/run/sshd` et l'hote refusait toute
connexion. La conversion arrete maintenant `ssh.service` explicitement, et
n'epargne le `MainPID` que si l'unite est vraiment active. En cas d'echec, elle
libere le port, recree `/run/sshd`, rend le port a `ssh.socket` et verifie
qu'un listener systemd ecoute avant de le dire. Elle attend aussi la fin de
cloud-init. Setup lance pendant cloud-init echouait aussi
sur `E: Could not get lock /var/lib/dpkg/lock-frontend`. Il attend maintenant la fin de cloud-init, et
un drop-in `50shuttle-dpkg-lock` fait attendre le verrou dpkg (600 s) a chaque
appel apt au lieu d'echouer. Enfin, un setup refuse n'affiche plus toute
l'aide des options apres l'erreur, qui noyait la commande `--adopt` a copier.

## Les digests infra stales polluaient setup et deploy, le premier deploy signalait un faux retard

Apres quelques jours, les digests Caddy, Redis, RabbitMQ et registry embarques
par v0.0.56 etaient deja en retard ou impossibles a verifier. Setup et deploy
affichaient alors des lignes WARNING, puis installaient quand meme l'ancien
digest. Le CLI resout maintenant les tags officiels sur Docker Hub avant de
generer le stack signe. Redis et RabbitMQ gardent leur majeure retenue; une
majeure suivante est signalee en information et demande une migration explicite.
Le stack conserve le digest exact pour le rollback et la recuperation. Un hote
existant garde son digest courant si Docker Hub est inaccessible; un hote neuf
recoit une erreur explicite. Les anciennes configurations qui ne contiennent
qu'un digest Caddy sont migrees silencieusement vers le tag de majeure. Les
references registry des plans sont validees sur le chemin stack-apply et juste
avant leur usage. Setup et deploy refusent les retours de version et les
changements de majeure implicites, puis convergent le conteneur Shuttle en
gardant son volume nomme apres verification de son montage et ses options de
securite. La recuperation lit RepoDigests depuis l'inspection de l'image
identifiee par le conteneur. Setup ne traite un hote comme neuf qu'apres avoir
confirme l'absence de stack, registre et manifestes conserves sur l'hote; sinon
l'audit des images retenues doit reussir. Les tags explicitement configures
restent exacts.

Le premier deploy peut depasser le SLO total pendant le pull froid: la promotion
v0.0.56 a mesure 33,46 s pour un budget de 30 s, dont 19,05 s pour la promotion.
Le helper indique maintenant `first_release` et le CLI affiche le temps sans
evaluer ce SLO pour la premiere release. Les deploys suivants gardent la mesure
et le signal existants. Les reponses des anciens helpers restent compatibles.

## `doctor --strict` refusait les applications internes et les hotes Ubuntu ne suivaient pas la politique annoncee

Le 28-10-2026, une recette sur VM avec v0.0.56 a montre deux refus sur un
hote fraichement prepare: l'audit readiness exigeait un domaine public pour
une application `expose: internal`, et le controle des mises a jour trouvait
encore l'origine APT generale fournie par Ubuntu 24.04. L'audit accepte
maintenant un domaine vide uniquement avec un chemin de sante vide; le helper
verifie les labels des services deployes, refuse toute publication incoherente,
puis marque TLS, HSTS, DNS et la sante publique comme non applicables avec une
preuve explicite. Les domaines non vides gardent leur validation existante.

Setup ecrit maintenant hors du checkpoint `10-base` un drop-in Shuttle
security-only adapte a Ubuntu 24.04 ou Debian 13, avec le redemarrage
automatique desactive. La comparaison avant remplacement rend la convergence
repetable et permet a `shuttle setup --adopt` de corriger un hote deja prepare.
`doctor` conserve un controle strict et indique cette commande pour remedier a
une politique absente; les fichiers fournis par la distribution restent
intacts. Les autres operations d'audit et le fichier `20auto-upgrades` restent
compatibles.

## Reexecuter setup sur un VPS Shuttle donnait un refus SSH opaque et un faux cutover

Le 28-10-2026, sur la VM e2e avec v0.0.56, relancer `shuttle setup` avec les
memes arguments echouait sur le handshake SSH root: le setup avait deja ferme
cet acces, mais le preflight affichait une erreur brute. Si l'identite locale
de confiance confirme que Shuttle a configure cet hote et que l'authentification
root echoue, le refus indique maintenant clairement la fermeture volontaire et
imprime la commande `shuttle setup --adopt` avec la cible operateur, l'hote et
les options de cle requises. Il n'y a ni nouvelle tentative ni ouverture de SSH
root.

Le plan d'adoption classait les taches Swarm d'une application comme etrangeres,
car il ne lisait que le label de proprietaire des conteneurs de service. Il
reconnait maintenant le namespace de stack quand le repertoire d'etat Shuttle
de l'application existe sous `/var/lib/shuttle/apps`. Les stacks sans ce
repertoire restent dans la liste des conteneurs etrangers. Si une tache Caddy
de `shuttle-edge` sert deja 80 et 443, l'adoption ne planifie aucun transfert
de ports. Un hote dont toutes les etapes sont satisfaites, sans travail differe
ni redemarrage en attente, est annonce comme deja converge, sans section
restante. Les noms de drapeaux et la fermeture SSH root restent compatibles.

## L'installation du monitoring activait un webhook absent et omettait l'operateur SSH

Le 28-10-2026, une installation v0.0.56 sur une VM preparee par `setup
--operator-user ops` signalait `security.ssh [degraded]`: l'operateur existait
sur l'hote mais seulement en flag, pas dans la config, et la liste attendue
par defaut ne lisait que la config. Elle ajoute maintenant les comptes que
setup a enregistres dans l'identite de l'hote, qui reflete ce que l'hote a
vraiment; les comptes declares dans la config (dont `retained_users`)
restent. Une liste `monitoring.security.expected_ssh_users` explicite reste
prioritaire.

La meme recette acceptait `notifications.webhook_env` alors que la variable
n'existait pas dans l'environnement systemd du VPS. Le timer demarrait ensuite
un service en echec a chaque cycle. Le helper root verifie maintenant avant
toute ecriture ou activation que le fichier secret root existe et contient une
URL HTTPS, ou que la variable est presente dans l'environnement du gestionnaire
systemd. L'unite transmet cette variable avec `PassEnvironment`. En cas
d'echec, le message indique comment configurer le fichier secret ou la variable
puis relancer `shuttle monitoring install --yes`, sans afficher l'URL.

Si le secret disparait apres l'installation, le cycle continue d'echouer et le
service systemd reste en echec, car la notification est indisponible. Le
rapport persiste aussi `notifications.delivery` comme indisponible afin que
`monitoring status` expose l'incident.

## La creation d'une sauvegarde echouait sur un hote correctement configure

Les 12 tentatives sur 12 de la VM e2e du 28-10-2026 ont echoue. Le motif strict
rejetait les UUID dont le premier caractere hexadecimal etait un chiffre, soit
10 des 16 valeurs possibles. Les autres atteignaient la capture, puis le helper
rejetait la publication du chiffrement: la capture et le chiffrement
etaient publies sous la meme phase. Le statut d'echec local marquait ensuite le
chiffrement termine, alors que le journal du helper ne l'avait jamais admis;
les operations restaient `recovery_required`.

Les tentatives portent maintenant le prefixe fixe `backup-`, et le chiffrement
a sa propre phase avant le recu. Cela garde le motif strict et donne au helper
une transition distincte a valider avant le recu ou un echec ulterieur. Le
schema JSON, ses noms de champs et les phases des journaux v0.0.56 restent
compatibles.

## Le premier deploy sur un hote neuf annoncait un nettoyage reporte

Sur l'e2e du 28-10-2026 (VM Ubuntu 24.04 neuve, v0.0.56), le premier deploy
affichait `image store reclaim deferred to the next sweep: no retained release
digest could be read`. Le balayage qui precede la promotion tournait alors
qu'aucune stack n'etait encore retenue sur l'hote: il n'y avait rien a liberer,
mais l'ensemble vide etait traite comme une lecture ratee. Quand aucun fichier
`current.yml` ou `previous.yml` n'existe, ni pour l'app ni pour une autre, le
helper journalise maintenant `image store: nothing to sweep yet` et ne signale
rien. Des fichiers retenus qui existent mais ne donnent aucun digest arretent
toujours le balayage, comme avant.

## Le monitoring alertait pendant un deploy, et ses alertes Discord etaient illisibles

Le 28-10-2026 a 10:42, pendant un redeploy d'api sur la prod demo, le
canal critique a recu `[shuttle] api services.application degraded:
Service task health does not match the retained expected replicas`, puis une
reprise une minute plus tard. Un seul echantillon, pris a 10:41:52 en plein
rollout, avait vu une nouvelle tache de `api_worker-high` encore en
demarrage. Trois defauts se combinaient.

Le debounce (30 s) etait mesure entre le premier echantillon en echec et le
premier echantillon sain suivant. Avec un intervalle de 60 s, cet ecart vaut
toujours 60 s: n'importe quel echantillon isole devenait un incident. Le
debounce compare maintenant la duree d'echec reellement observee, du premier
au dernier echantillon en echec (le `last_seen` precedent, puisqu'un incident
actif veut dire que l'echantillon d'avant etait en echec). Il faut deux
echantillons en echec qui couvrent le debounce pour alerter. Le fichier d'etat
garde son format v1: un retour a l'ancien binaire le relit sans erreur.

Une tache que Swarm est en train de demarrer (`preparing`, `starting`...),
sans erreur, etait comptee comme malsaine, de meme qu'un conteneur dans la
periode de demarrage de son healthcheck (`starting`). Les deux sont une
convergence, pas une panne: Swarm et Docker les font echouer eux-memes si
elles n'aboutissent pas. Une tache en echec reste degradee, et un service sans
aucune tache en marche le reste aussi, avec le resume `Service tasks are still
starting`.

Un episode reprenait l'identifiant de l'enregistrement sain cree des heures
plus tot (`episode_id` du 27-10 a 22:28 pour une panne du 28-10 a 10:41). Il
commence maintenant au premier echantillon en echec.

Les alertes Discord sont des embeds: un titre en clair (`api: application
service degraded`), une couleur qui ne porte que l'etat (ambre degrade, rouge
indisponible ou critique, vert reprise), le constat mesure, l'app, le check,
le debut de l'episode en heure relative, et pour une reprise sa duree
(`Healthy again after 1m12s.`). Le champ `content` reste vide pour ne pas
repeter le titre. Slack et Mattermost lisent la meme phrase dans `text`, et
les champs JSON de la notification restent identiques, plus `created_at`.

Enfin, les sondes de securite lancaient `sudo -n true` meme en root. Dans
l'unite du monitoring (`NoNewPrivileges`), sudo ne peut pas s'executer: chaque
run journalisait 3 a 4 `unable to open /etc/sudoers : Operation not
permitted`, puis l'echec du mail que sudo envoie a root (exim `Permission
denied`). En root, les sondes n'appellent plus sudo, et la lecture de la
politique sudo du compte deploy (`sudo -l -U`) se saute sans bruit sous
`NoNewPrivileges`; le resultat des checks ne change pas, ils passaient deja
par le chemin direct.

## Les anciennes images Redis, RabbitMQ et Caddy s'accumulaient sur le noeud

Le 27-10-2026, sur la prod demo, des conteneurs `exited` de
`shared_rabbitmq`, `shared_redis` et du Caddy partage, vieux de 4 jours a 4
semaines, retenaient encore les images rabbitmq 3, 4.0 et 4.1 et d'anciennes
images caddy. Dockerd garde l'image tant qu'un conteneur de tache arrete
existe, et le balayage du helper (DEV-DEPL-54) laissait volontairement
l'infrastructure de cote: chaque montee de version laissait donc son image
sur le disque, jusqu'a ce que la garde des 20 % d'espace libre refuse un
deploy (DEV-DEPL-55).

Une passe separee, a cote du balayage existant qui reste inchange, retire
sans `--force` les conteneurs de tache arretes de `<app>_redis`,
`<app>_rabbitmq` et `shuttle-edge_caddy`, puis les images redis, rabbitmq et
caddy que plus rien ne retient. Sont toujours gardees: l'image de tout
conteneur qui n'est pas arrete, chaque digest des `current.yml` et
`previous.yml` de toutes les applications et de `/etc/shuttle/caddy-stack.yml`,
et les images `Spec` et `PreviousSpec` de chaque service Swarm, pour que
`docker service rollback` reste possible. Une lecture qui echoue ou une
donnee mal formee (service sans image, ligne illisible) annule la passe au
lieu d'etre ignoree: on ne peut pas prouver qu'une image est inutile sans
l'avoir lue. Avec des promotions concurrentes, la passe sur les images ne
tourne que sous la cloture d'operation unique, pour qu'un deploy en train de
tirer une image d'infrastructure ne la perde pas. Le journal du helper porte
une ligne `infra images: N kept, N stopped infrastructure task containers
removed, N images removed, N still held by a container`.

Le setup copie maintenant `/etc/shuttle/caddy-stack.yml` avant le script des
volumes et le pull, pour que ce fichier existe des que l'image Caddy est sur
le noeud. Effet au premier deploy apres `shuttle helper update` en v0.0.56;
les volumes ne sont jamais touches.

## Un deploy lent ne disait pas pourquoi

Le 27-10-2026, un deploy d'demo-agent a pris 7m57 au lieu de 6m40: l'image
de base flottante `python:3.12-slim-bookworm` avait bouge en amont, et toute
l'image de 6,8 Go avait ete reconstruite, dont une couche Playwright de 3,36 Go.
La sortie ne donnait que des durees, et le message de SLO manque conseillait de
relever `deploy.total_slo_seconds` "if this is normal", ce qui pousse a masquer
la cause; il a fallu comparer les couches du noeud a la main (DEV-DEPL-53,
partie B).

Les builds Swarm locaux et Compose lisent maintenant la progression BuildKit
(analyse au fil de l'eau, sans garder la transcription; une ligne inconnue
n'a aucun effet, et une erreur d'affichage ne change jamais le resultat du
build). Une ligne `Build detail:` suit chaque `Timing build.<service>`: etapes
en cache, etape la plus lente (y compris une etape en cache qui extrait
longtemps ses couches parentes, comme `COPY models/` a 14,1 s), et `stage <nom>
rebuilt from its base: base image changed or build cache was cold` quand la
premiere instruction apres le FROM d'un stage (etape 2/n) a ete executee
(`(full rebuild)` si rien n'est en cache); Shuttle nomme le stage et ne pretend
pas savoir laquelle des deux causes. Le FROM seul ne prouve rien: sur un build
chaud, BuildKit affiche `FROM ... DONE 0.0s` alors que tout le reste est en
cache. Un COPY ou un ADD relance en etape 2 non plus: un contexte modifie suffit.
Avec le push direct de BuildKit, le temps de push mesure par BuildKit
(`pushing layers`, `pushing manifest`) apparait a part (`registry push 41.5s of
it`), dans la ligne de detail comme dans la cause du SLO, pour qu'un envoi lent
ne passe pas pour un build lent. Un build qui echoue affiche aussi sa ligne de
detail. La ligne porte le nom du service (`Build detail.<service>:`), pour
rester lisible quand plusieurs builds tournent en parallele. Un SLO de promotion
manque nomme la promotion; un SLO total manque en Swarm nomme l'etape dominante
(build, push, promotion, ou "setup and other steps" pour le temps non suivi) et
la cause du build; en Compose, il ne nomme pas d'etape faute de mesure. Les
builds captures forcent `--progress=plain`, en remplacant tout autre format.
Aucun message ne suggere plus de relever le budget.

Effet visible: la sortie de buildx passe par un tube, donc buildx affiche sa
progression en texte simple au lieu de la vue animee, meme dans un terminal
interactif; c'est aussi ce qui rend l'analyse fiable. Le build distant par SSH
et `deploy existing-stack` sont inchanges. Le partage pull / demarrage de la
promotion demande un champ du protocole du helper (DEV-DEPL-60).

## Le balayage de la registry loopback pouvait supprimer les manifestes d'une autre application

Releve le 27-10-2026 par la revue du balayage des images (DEV-DEPL-54): apres
une promotion, le helper choisissait les depots de l'application par le
prefixe `app-` du catalogue, si bien qu'une application `api` balayait aussi
les depots d'`api`, et il lisait une seule fois l'ensemble des digests a
garder alors que les promotions d'applications differentes tournent en
parallele. Un manifeste qu'une autre application venait de pousser et de
retenir pouvait etre supprime (DEV-DEPL-57).

L'appartenance d'un depot vient maintenant des fichiers retenus de
l'application elle-meme (`current.yml`, `previous.yml`): un depot qu'une autre
application retient aussi est partage, journalise et laisse aux deux. Chaque
passe de suppression (manifestes remplaces, puis eviction du cache de build)
s'execute seule sur l'hote quand des operations concurrentes sont possibles, et
relit l'ensemble a garder et l'appartenance a l'interieur de cette fenetre; une
relecture vide ou en echec reporte la suppression et le GC au balayage
suivant. L'eviction ne supprime jamais un digest qu'une stack retenue
reference. Les noms de depots, de tags et de digests sont valides avant de
construire une URL. Un fichier retenu corrompu d'une autre application arrete
le balayage; un fichier absent (premier deploy) est ignore.

Compromis assume: un depot que l'application ne retient plus (service retire)
n'est plus balaye, une fuite plutot qu'une suppression a tort (DEV-DEPL-63).
Effet sur un noeud apres `shuttle helper update`.

## Un deploy de code seul passait 70 secondes a recharger une image deja publiee

Le 27-10-2026, sur la prod demo, un deploy d'demo-agent sans changement de
couche prenait 1m12, dont 57 s de build alors que les 16 etapes etaient en
cache: 17,5 s pour rapatrier les couches du cache par le tunnel SSH, 53,9 s
pour exporter l'image de 6,8 Go en OCI et l'importer dans le Docker local, puis
un `docker push` qui repondait `Layer already exists` pour chaque couche
(DEV-DEPL-53, partie A).

Le build Swarm local publie maintenant directement depuis BuildKit (`--push
--metadata-file`) au lieu de `--load` puis `docker push`. Le manifeste
precedent est preserve avant, comme sur le chemin de build distant. Le digest
`containerimage.digest` que BuildKit a pousse est compare au digest que la
registry annonce (HEAD): une difference, ou un digest absent, fait echouer le
deploy avant la promotion, et la stack ne peut promouvoir que ce digest
verifie (un tag reecrit entre les deux lectures est refuse). Les tags jamais charges en local ne sont plus
nettoyes. Mesure sur la meme prod: 14,8 s au total (build 5 s, push 10 ms,
promotion 4,3 s), meme digest, identite de la release verifiee. Avec un vrai
changement de code (une couche modifiee): 47,3 s au lieu de 72 s.

Le mode Compose et `deploy existing-stack` gardent `--load`; le build distant
par SSH poussait deja directement. `--skip-build` pousse comme avant une image deja construite.

## Le check security.ufw du monitoring etait toujours `unavailable` sous le timer

Le 27-10-2026 sur la prod demo, avec le monitoring d'api active, le
check security.ufw etait sain via `shuttle monitoring run` mais `unavailable`
(`UFW posture could not be inspected`) a chaque cycle du timer, et un incident
est parti. L'unit systemd du monitoring tourne en `ProtectSystem=strict` et
n'ouvrait en ecriture que son dossier d'etat et `/run/shuttle-root.lock`; or
`ufw status` ouvre `/run/ufw.lock` en ecriture: `Read-only file system`
(DEV-DEPL-58). Le chemin du helper, non isole, cachait le defaut.

L'unit ouvre maintenant aussi `-/run/ufw.lock` (le `-` garde l'unit
demarrable sur un hote sans ufw), et l'entree tmpfiles cree ce verrou apres un
reboot, avant la construction du sandbox, comme celui de Shuttle;
l'installation applique aussi cette regle tout de suite (`systemd-tmpfiles
--create`), sinon un hote installe apres le boot restait `unavailable` jusqu'au
reboot suivant, le `-` taisant le fichier absent. Un test
verifie que chaque verrou ecrit par un check est ouvert en ecriture et cree
par tmpfiles. Rien d'autre ne s'ouvre. Sur un hote deja equipe: apres `shuttle
helper update`, relancer `shuttle monitoring install --yes` reecrit l'unit.

## Le balayage des images du noeud ne liberait presque rien

Le 27-10-2026 sur la prod demo (198.51.100.10), le journal du helper disait a
chaque balayage `12-13 superseded images found, 0-1 removed, 12-13 still held
by a container`, toujours les memes digests. La limite d'historique Swarm etait
bien a 2, mais chaque slot gardait trois conteneurs arretes, et certains
appartenaient a des taches que Swarm avait deja oubliees (orphelins, par
exemple `demo-agent_agent.1.pty4ai00...` pour la release afba2df1). 38
conteneurs arretes sur 56; les trois anciennes releases d'demo-agent
retenaient a elles seules 6,78 Go. Le balayage refusait a juste titre de forcer
une image tenue par un conteneur, et rien dans Shuttle ne supprimait ces
conteneurs (DEV-DEPL-54).

Les deux balayages (avant le deploy et apres la promotion) suppriment
maintenant d'abord les conteneurs de taches Swarm arretes qui tiennent une
release remplacee, puis les images. Un conteneur n'est supprime que s'il est
`exited` ou `dead`, porte le label de tache Swarm et tourne une image de la
registry loopback qu'aucun `current.yml` ni `previous.yml` ne retient; jamais
avec `--force`. La release precedente reste sur le noeud pour un rollback
rapide; un conteneur en marche, lance a la main ou d'infrastructure partagee
n'est jamais touche. L'ensemble a garder est relu juste avant chaque passe de
suppression et l'echange des fichiers d'un rollback se fait sous le meme verrou
que les balayages, pour qu'une promotion ou un rollback concurrent d'une autre
application ne perde pas sa release. L'inspection des conteneurs est bornee a
60 s par balayage. Pas de timer: les releases n'arrivent que par des deploys,
et chacun balaie avant et apres. Le seuil de refus a 20 % d'espace libre est
une seule constante pour le CLI et le helper.

Effet sur un noeud apres `shuttle helper update` en v0.0.52, au premier deploy
suivant. L'infrastructure partagee (RabbitMQ, Redis, Caddy...) reste hors de ce
balayage; une passe separee la couvre depuis v0.0.56 (DEV-DEPL-55, plus haut).

## Les alertes du monitoring echouaient en silence sur un webhook Discord ou Slack

Le 27-10-2026, en preparant le monitoring disque de la prod demo, le corps
du webhook s'est revele etre le JSON brut de la notification (`id`, `kind`,
`app`, `check_id`, `episode_id`, `state`, `summary`). Discord refuse un message
sans `content` et Slack attend `text`: chaque alerte aurait echoue, avec pour
seule trace le journal des echecs de livraison (DEV-DEPL-56).

Le corps garde tous ces champs pour un recepteur generique et ajoute `content`
et `text`, une ligne lisible: `[shuttle] <app> <check> <etat>: <resume>`,
coupee a 1900 caracteres sur une limite de caractere (Discord plafonne a 2000).
Un recepteur qui lisait les champs existants n'y voit que deux cles de plus.

## Un deploy rate apres un rollback d'urgence affichait trois erreurs trompeuses et jamais la commande de recovery

Le 27-10-2026, sur une VM jetable, un deploy dont la promotion a ete annulee
par Swarm a declenche le rollback d'urgence du helper, qui a ferme l'operation
en `recovery_required` (voulu: `operations recover` inscrit ensuite l'infra
gardee). Le CLI continuait pourtant a la piloter et affichait, apres la vraie
erreur, `operation-renew failed` deux fois puis `operation-abort failed:
operation is not active for this phase`, plus tout l'usage de `shuttle
deploy`, sans jamais nommer `shuttle operations recover` (DEV-DEPL-47). Meme
silence apres un `helper update` rate: l'operation `helper-update` restait
`recovery_required` et chaque deploy suivant etait refuse sans consigne.

Le helper repond maintenant `operation requires recovery` a un controle sur
une operation deja `recovery_required`, au lieu du message generique qu'il
garde pour les operations terminees. Le CLI reconnait cette reponse, et
l'ancienne (helpers jusqu'a v0.0.50) apres une lecture signee de l'etat bornee
a 15 secondes, arrete d'envoyer des controles, et ajoute une seule ligne apres
l'erreur reelle. Elle depend du type d'operation: deploy et consorts
`recover <id> --dry-run` puis `--yes --plan-digest`; `helper-update`
seulement `--dry-run` (sa preuve de reservation survit a l'echec de la sonde,
donc `--yes` serait refuse); reboot `operations reboot --resume`; destroy et
restore renvoient a `operations status`. Si l'etat ne peut pas etre lu, la
ligne le dit (`may require recovery`). La meme ligne suit un `operation-abort`
reussi, qui met lui-meme l'operation en `recovery_required`, et un deploy
bloque par une operation non recuperee. La fermeture des writers se fait
toujours avant, sinon la recovery nommee serait refusee. `deploy`, `deploy
existing-stack` et `helper update` n'affichent plus l'usage sur une erreur
d'execution, et l'erreur n'est plus imprimee deux fois (cobra puis `main`).

Aucune transition d'etat ne change: `recovery_required` reste ferme, abort,
refuse et finish le refusent toujours. Les lignes ne reprennent pas encore
`--config`/`-e` (DEV-DEPL-50).

## Un helper update rate cachait la vraie cause derriere un message generique

Le 27-10-2026, sur une VM jetable, `shuttle helper update` a echoue avec
`replacement binary does not expose the shuttle-root interface`. Lance a la
main, le candidat disait la vraie cause: `/usr/local/libexec/shuttle-root
exceeds the 33554432 byte limit`. Le helper installe sonde le candidat avec
`shuttle-root --help` avant de le remplacer, et jetait l'erreur comme la sortie
de la sonde (DEV-DEPL-48).

Les deux sondes (mise a jour directe et preuve de migration) passent
maintenant par une seule capture, bornee a 64 KiB, et l'erreur porte un extrait
de la sortie: UTF-8 valide, sans caractere de controle ni de format (categorie
Unicode C, comme le reste du journal du helper), espaces fusionnes, 240 octets
au plus coupes sur une limite de caractere. La sortie du candidat reste une
donnee non fiable: elle atteint le terminal de l'operateur et le journal, d'ou
ce nettoyage. Un candidat qui n'imprimerait son marqueur qu'apres 64 KiB est
refuse; un vrai shuttle-root l'imprime en premiere ligne.

Rien ne change dans ce qui est verifie avant la sonde, ni dans l'ordre sonde
puis remplacement. Le detail n'apparait qu'une fois le helper installe en
v0.0.51 ou plus: la mise a jour depuis un helper plus ancien garde l'ancien
message. Pas de timeout sur la sonde pour l'instant (DEV-DEPL-51).

## Setup tuait un sshd orphelin sans le dire quand il reussissait

Le 27-10-2026, sur une VM Ubuntu 24.04 jetable, setup a trouve un listener
sshd orphelin sur le port 22, l'a arrete (PID 11025) puis a converge. La ligne
`stopping orphan sshd listener PID 11025` n'existait que sur le stderr du
script, et setup n'affichait ce stderr qu'en cas d'echec: le seul run qui avait
tue un processus sur l'hote n'en laissait aucune trace a l'ecran.

Setup recopie maintenant ces lignes, et seulement elles, dans sa sortie
(`  -> stopping orphan sshd listener PID ...`). Le reste du stderr d'un run
reussi est le bavardage de systemctl (`Removed ...`, `Created symlink ...`) et
reste masque. Le script et ses conditions sont inchanges; un hote sans orphelin
affiche exactement la meme sortie qu'avant.

## Le rollback d'urgence d'un deploy rate pouvait retrograder Redis ou RabbitMQ

Le 27-10-2026, sur une VM jetable, `previous.yml` epinglait
`redis:8.10.1-alpine` alors que le service avait ete mis a jour a la main en
8.10.3. Un deploy dont le serveur web meurt au demarrage a echoue a la
promotion; le rollback d'urgence du helper a redeploye `previous.yml` tel quel,
et `docker service inspect` montrait ensuite 8.10.1 en service et 8.10.3 en
precedente: Redis avait ete retrograde sur ses donnees persistantes
(DEV-DEPL-46). `operations recover` gardait deja une image vivante plus recente
depuis v0.0.48; ce chemin-la reappliquait les images de `previous.yml` sans
regarder ce qui tournait. Seul production-host etait expose en production, jusqu'a
son prochain deploy reussi.

Avant le rollback, le helper lit maintenant l'image en service de chaque Redis
et RabbitMQ du fichier de rollback, avec la decision de `operations recover`
(fonction partagee, verdicts et messages de la recovery inchanges). L'image de
`previous.yml` n'est appliquee que si les deux sont officielles, epinglees par
digest, de meme majeure, et la retenue strictement plus recente. Dans tous les
autres cas (vivante egale ou plus recente, majeure differente, image non
officielle, version illisible), l'image en service est gardee dans un manifeste
temporaire 0600 du repertoire d'etat, supprime apres la tentative, et la raison
va au journal `shuttle-root`. Un changement de majeure n'est donc jamais
applique en silence. Le chemin d'urgence ne peut pas refuser comme la recovery:
la release echoue deja et personne n'est la pour trancher. Laisser un service
avec etat sur ce qu'il execute est le seul choix qui ne peut pas abimer ses
donnees.

Quand la protection ne peut pas etre etablie (`previous.yml` illisible ou hors
de la forme validee, image vivante illisible ou impossible a ecrire, manifeste
impossible a construire), le rollback est saute et journalise
`emergency rollback SKIPPED`: la release en echec continue de servir, et
`shuttle operations recover` ou un redeploy reste le chemin explicite. C'est
plus long qu'un rollback automatique, mais un downgrade de donnees ne se
rattrape pas.

`previous.yml` et `current.yml` ne sont pas reecrits: les digests du journal
restent valides. Quand toutes les images en service egalent celles du fichier
de rollback, ou sans Redis ni RabbitMQ, le rollback est exactement celui
d'avant: meme fichier, meme commande docker. `shuttle rollback` et
`operations recover` gardent leur comportement.

## Le helper ne synchronisait pas le repertoire apres avoir remplace current.yml ou previous.yml

`writeRootFile` ecrit `current.yml` et `previous.yml` par un fichier temporaire
synchronise puis un renommage, sans jamais synchroniser le repertoire parent.
Le `Sync` du fichier rend son contenu durable, pas le renommage: c'est une
modification du repertoire, qui n'atteint le disque qu'au prochain flush de ses
metadonnees. Le deploy journalise le digest de `current.yml` avant de l'ecrire;
apres une coupure de courant dans cette fenetre, le fichier pouvait revenir a
son ancien contenu alors que le journal nommait deja le nouveau. Constate par
lecture du code (DEV-DEPL-45); `replaceRootHelper` et la reecriture faite par
la recovery synchronisaient deja leur repertoire, ce chemin etait le dernier.

`writeRootFile` synchronise maintenant le repertoire apres le renommage, et un
echec est renvoye a l'appelant avec une erreur qui dit que le fichier est deja
remplace. La review a montre que cette nouvelle erreur pouvait couper en deux
l'echange de `current.yml` et `previous.yml` d'un `shuttle rollback`: les deux
fichiers auraient porte la cible du rollback et la release annulee aurait
disparu. L'echange termine donc toujours sa seconde ecriture apres un echec de
synchronisation de la premiere, puis renvoie les deux erreurs. Le deploy, lui,
s'arrete avant `docker stack deploy`, dans l'etat qu'un crash au meme point
laisse et que la recovery sait deja traiter.

Rien ne change pour les formats, les modes ni les chemins; seul un `fsync` de
repertoire en echec, jusqu'ici ignore, devient une erreur visible.

## setup echouait sur une Ubuntu 24.04 neuve quand un sshd orphelin tenait le port 22

Le 27-10-2026, deux setups sur deux d'Ubuntu 24.04 neuves se sont arretes a la
conversion de `ssh.socket` vers `ssh.service` (DEV-DEPL-44): "Job for
ssh.service failed because the control process exited with error code". Le
journal disait "Found left-over process 8655 (sshd) in control group", puis
"Bind to port 22 on 0.0.0.0 failed: Address already in use". La mise a niveau
des paquets de l'etape base avait relance un listener `sshd -D` de PPID 1 dans
le cgroup de `ssh.service` sans qu'il en soit le MainPID. Ubuntu livre l'unite
avec `KillMode=process`: ni l'arret ni le restart ne le tuent, et le nouveau
sshd ne pouvait pas ecouter. L'hote restait a moitie converti, et un second
setup ne reparait rien, puisque `ssh.socket` etait deja desactive. Le
contournement manuel, `kill 8655; systemctl start ssh.service`, gardait la
session ouverte: les sessions sont des enfants du listener et lui survivent.

Apres `disable --now ssh.socket`, setup lit maintenant les PID en ecoute sur
TCP 22 et le MainPID de `ssh.service`, et n'envoie SIGTERM qu'a un listener
prouve orphelin, lu dans `/proc`: PPID 1, comm `sshd`, cgroup exactement
`0::/system.slice/ssh.service`, ligne de commande d'un listener sshd. L'identite
est relue juste avant le signal, heure de demarrage comprise, pour qu'un PID
reutilise ne soit jamais vise. Tout autre processus sur le port 22 (autre
demon, sshd d'une autre unite, session) arrete setup avec son PID et ce qui a
ete lu, sans etre tue: se tromper couperait le seul transport vers l'hote. Ni
`systemctl kill`, ni `pkill sshd`. Apres le restart, setup exige que chaque
listener du port 22 soit le nouveau MainPID. La conversion tourne aussi quand
`ssh.service` est inactif, pour qu'un setup interrompu se repare au passage
suivant. La premiere version lisait `ps`, dont les colonnes alignees et
tronquees auraient fait refuser l'orphelin reel: la review l'a vu, `/proc` ne
tronque rien.

Sans orphelin, les commandes et leur ordre restent identiques: seules des
lectures s'ajoutent. Un hote deja sur un `ssh.service` actif n'est pas touche.
La fenetre entre la derniere lecture et le signal reste ouverte (pas de pidfd
en sh POSIX); elle est documentee et acceptee.

## La recovery laissait current.yml epingler une ancienne image Redis

Le 26-10-2026, sur production-host, `current.yml` epinglait Redis 7.4.5 alors que
`demo_redis` executait deja Redis 7.4.11. Depuis v0.0.48, recovery conservait
cette image officielle, epinglee par digest, de meme majeure et au moins aussi
recente. Elle ne changeait que la copie `.recovery-*`; le fichier retenu gardait
7.4.5, ce qui permettait a un autre chemin ou a un futur rollback de redemander
une image plus ancienne.

Pour un enregistrement `deploy`, quand `current.yml` est le manifeste retenu,
recovery lie maintenant au plan les references Redis et RabbitMQ conservees,
inscrit le digest complet du nouveau `current.yml` dans un champ distinct du
journal, puis remplace uniquement les octets des valeurs `image` et synchronise
le repertoire. Le digest d'origine du deploiement echoue reste intact. Si le
processus s'arrete entre journal et renommage, le meme geste est rejoue; apres
le renommage, le digest lie autorise exactement ce fichier. Les images non
officielles, sans digest, de majeure differente ou plus anciennes restent
refusees. Toute autre modification de `current.yml` sans digest exact deja
autorise reste inconnue et refusee. Si le manifeste vient de l'archive de base,
recovery conserve le comportement existant et ne le recopie pas dans le slot.

Le changement ajoute un champ de journal strictement decode. Un ancien helper
ne peut pas lire ce champ: son downgrade apres cette version n'est pas supporte.
Un ancien CLI ne peut pas lire le statut d'un nouveau helper: mettre le CLI a
cette version ou plus recente avant `operations status` ou recovery contre un
helper mis a jour. Les anciens enregistrements sans ce champ restent lisibles,
et les enregistrements `rollback` gardent leur comportement actuel. Le nouveau
`current.yml` ne protege un rollback qu'apres que le prochain deploiement l'a
tourne dans `previous.yml`, car rollback applique ce slot.

Une mise a jour concurrente par `docker service update` entre le dernier
inspect et l'ecriture du manifeste reste une fenetre residuelle acceptee par
decision operateur du 27-10-2026.

## Un echec avant promotion bloquait durablement le deploiement

Le 27-10-2026, un premier deploiement VM de `e2e48b` a echoue pendant le build
sur une reponse Docker Hub 429. Le build n'avait pas touche a l'application,
mais l'operation est restee `recovery_required` et le deploiement suivant a ete
bloque. Un `RUN false` dans l'image d'une application deja en service a aussi
laisse `e2e48c` en `recovery_required`. Enfin, une premiere installation avec
une ancienne image Redis officielle epinglee a ete refusee faute d'image
retenue, puis les controles de renouvellement et d'abandon ont echoue parce que
la phase `stack-apply` avait deja ete ouverte.

La cause etait double: le client abandonnait toute erreur, meme avant la
promotion, et le helper ouvrait la phase avant ses refus deterministes. Le
client ne prouve pas qu'aucune mutation n'a eu lieu: son transport peut tomber
apres l'envoi de la promotion alors que son champ local indique encore
`not-started`. Le coordinateur accepte maintenant le refus d'un deploiement
uniquement si son journal prouve une initialisation des writers terminee, puis
eventuellement le seul `stack-reclaim` termine, sans phase de publication de
secrets ni autre phase de mutation. Ce reclaim peut supprimer des images
obsoletes et regler l'historique Swarm, mais ne modifie aucun service ni stack.
Les controles deterministes du helper s'executent avant l'ouverture de la
phase, et le refus signe transporte seulement le motif borne du helper ou le
texte fixe `client failed before promotion`. La recovery d'un ancien abandon
utilise la meme preuve du journal, garde la preuve de fermeture des writers et
n'execute aucune action sur l'hote si aucune phase de mutation n'existe.

Un deploiement reussi conserve le meme journal et la meme sortie. Les echecs
apres une promotion tentee sans marqueur de refus, les nettoyages incomplets et
les phases de publication de secrets restent recuperables comme avant. La
regle de refus de `shuttle run` reste inchangee.

## RabbitMQ ne demarrait jamais avec le secret de mot de passe genere

Le 27-10-2026, un deploiement e2e sur VM avec `rabbitmq:4.3.5-alpine` a
echoue: `stack e2e48 did not converge within 16.5s`, avec `e2e48_rabbitmq: 0
of 1 task wanted running` et une tache en `Failed: task: non-zero exit (1)`.
Les journaux indiquaient que `RABBITMQ_DEFAULT_PASS_FILE` etait obsolete et
que l'image refusait les variables d'environnement obsoletees. Son script
officiel d'entree liste aussi `RABBITMQ_DEFAULT_USER_FILE` comme obsolete et
termine avec le code 1 avant de lancer le broker.

Le service lit maintenant le Docker Secret existant, valide sa valeur brute,
puis ecrit `default_user` et `default_pass` dans un fichier RabbitMQ temporaire
sur le tmpfs `/tmp`. Le broker charge ce fichier au demarrage. Cette voie suit
la demande de l'image et evite les variables `RABBITMQ_DEFAULT_USER` et
`RABBITMQ_DEFAULT_PASS`, reservees par la documentation RabbitMQ au
developpement et a l'integration continue.

Le nom du secret `<app>_rabbitmq_password_v1` et son contenu restent inchanges;
les applications qui montent `RABBITMQ_PASSWORD` continuent de lire la meme
valeur. Aucun hote n'ayant pu demarrer le RabbitMQ gere par Shuttle depuis
l'origine, aucune donnee existante n'est a migrer.

Le premier deploiement sur VM de ce script a lui-meme ete refuse par le
helper (`stack payload is empty, oversized, or contains unresolved
variables`) : le script utilisait `${#password}` et `${source_file##*/}`, et le
helper refuse tout `${` dans le stack. Le script n'utilise plus que des formes
sans accolades, et un test passe desormais chaque stack Redis et RabbitMQ
genere au validateur du helper. Sur VM, avec `rabbitmq:4.4.0-alpine`, le
service converge, `shuttle` s'authentifie, `guest/guest` est refuse et aucun
mot de passe n'apparait dans l'environnement du conteneur.

## La recovery pouvait downgrader Redis sur ses donnees persistantes

Le 26-10-2026, sur le VPS production-host avec le helper v0.0.47, un deploiement a
echoue au build, avant toute modification de l'hote, puis a laisse l'operation
en `recovery_required`. Le plan a reapplique `current.yml` du 22-10, qui
epinglait Redis 7.4.5, sur `demo_redis` deja passe a Redis 7.4.11. Cela a
remplace l'image en service au-dessus de donnees plus recentes. AOF et la meme
majeure ont permis au service de repartir, mais un downgrade pouvait casser
les donnees sur disque.

Pour les seuls enregistrements `deploy`, recovery inspecte chaque service Redis
ou RabbitMQ declare dans le manifeste retenu. Si les images en service et
retenue sont officielles, epinglees par digest et presentes localement, et si
leurs versions lues dans `Config.Env` partagent la meme majeure, recovery garde
l'image en service quand sa version est egale ou superieure. Ce choix est lie
au plan et revalide juste avant `stack deploy`. Le texte du plan n'affiche que
les versions; les references completes sont liees par la preuve. Le dry-run
ne contacte jamais de registre et ne fait aucun pull.

Un changement de majeure dans un sens ou dans l'autre, une image non officielle
ou sans digest, une inspection de service autre que l'absence, ou une version
locale manquante ou illisible bloquent le reapply et demandent une intervention
manuelle. Une image retenue de meme majeure plus recente que le service vivant
est reappliquee normalement. Si cette image retenue a ete supprimee du daemon,
ce cas bloque maintenant avec le message demandant a l'administrateur de la
tirer avant de relancer recovery. Les services absents gardent le comportement
precedent. Le manifeste retenu n'est jamais reecrit; `current.yml` et
`previous.yml` restent identiques pendant recovery.

Une mise a jour concurrente par `docker service update` apres le dernier
inspect et avant `docker stack deploy` reste une fenetre residuelle acceptee par
decision operateur du 26-10-2026. La fermer demande un verrou hote hors de ce
changement. La seconde etape, qui liera la reecriture eventuelle des manifestes
retenus au coordinateur, est differee a DEV-DEPL-41 apres la fusion de
DEV-DEPL-40. Les enregistrements `rollback` gardent leur comportement actuel
et peuvent encore downgrader Redis ou RabbitMQ; cette decision operateur du
26-10-2026 est egalement suivie dans DEV-DEPL-41.

## Un run en echec pouvait bloquer toutes les operations de son application

Mesure sur une VM le 2026-10-26 : `shuttle run fail`, dont la commande etait
`node -e process.exit(3)`, a affiche `operation fail failed: exit status 3`, puis
`operation-abort failed: operation is not active for this phase`. Le statut est
reste `recovery_required`, `shuttle deploy` a ete bloque, et le dry-run de
recovery a observe un etat sain avant de rester sans preuve pour liberer les
marqueurs. Un exit code seul ne prouve pas que le processus de commande s'est
termine : Docker renvoie aussi des codes pour ses propres erreurs ou une
connexion perdue. Le helper compare donc les ExecIDs avant et apres `docker
exec`; seul un code qualifie sans nouvel exec encore present, ou la disparition
du conteneur, donne un resultat connu. Apres fermeture des writers, le client
refuse alors explicitement le run : le journal passe a `failed` et l'application
redevient utilisable.

Pour une issue inconnue, le helper journalise le service et le conteneur avant
l'exec. `operations recover` garde les controles de writers, registry,
manifestes et PostgreSQL. Si le conteneur journalise tourne encore, il remplace
les taches du service, puis prouve que ce conteneur est arrete et que les
replicas sont sains avant de liberer l'operation. Un conteneur deja arrete ou
absent peut etre libere apres les memes controles. Aucune donnee n'est restauree
automatiquement; la restauration depuis une archive reste une decision explicite.

Le budget du helper reste dix minutes : une commande plus longue est tuee et se
recupere avec `shuttle operations recover`; les travaux longs doivent tourner
dans un service de la stack. Le plan signe ne change pas. Le CLI et le helper
doivent etre mis a jour ensemble, car un ancien CLI peut refuser de decoder les
nouveaux champs `known` et `run_target`. La sortie d'un run reussi reste
inchangee; son journal ne gagne que la cible necessaire a la reconciliation.

## Une migration PostgreSQL pouvait demarrer sans sauvegarde recente

`shuttle run migrate` lancait la migration directement : la sauvegarde la plus
recente etait celle du timer quotidien (`pg_dumpall`, jusqu'a 24 heures), et
`rollback` ne restaure jamais PostgreSQL. Une migration qui detruisait des
donnees n'avait donc aucun filet recent.

Une operation declaree peut maintenant porter `backup_before: true`. Avant le
`docker exec`, le helper fait un `pg_dump -Fc` de chaque base de l'application,
le relit avec `pg_restore --list`, puis le publie en 0600 dans
`/var/backups/shuttle-postgres/pre-run/<app>/` (cinq generations, separees des
sept archives quotidiennes). La liste des bases vient de l'hote (base derivee,
ledger et label signe `dev.shuttle.databases`), jamais du CLI : le ledger seul
oubliait une base adoptee. Le dump est refuse s'il laisserait moins de 10 % du
disque libre, si un autre dump ou le dump quotidien tourne, ou s'il depasse
cinq minutes ; pg_dump tourne sous l'identite `postgres` dans son propre groupe
de processus, tue en entier a l'echeance, car `runuser` ne transmet pas SIGKILL.

Un dump refuse ne bloque plus l'application. Ce pre-flight tourne avant la phase
de mutation, et le refus se termine par la nouvelle action `operation-refuse`
(etat `failed`, sans `recovery_required`), que le coordinateur n'accepte que pour
un `run` dont les seules phases sont des `writers-initialize` terminees et dont
les writers sont fermes. Sans elle, le client envoyait `operation-abort`, et
`shuttle operations recover` ne sait pas reprendre un `run` (DEV-DEPL-40).

`shuttle run` gardait aussi le delai de transport SSH par defaut de deux
minutes : au-dela, le CLI annoncait un echec et abandonnait l'operation pendant
que le helper continuait en root. Le delai est maintenant derive des budgets du
helper (19 minutes), et le plan signe vaut 15 minutes, le plafond du protocole.

Compatibilite : une operation sans `backup_before` produit les memes octets de
label et de plan qu'avant. Un deploy qui declare l'option exige la capacite
`pre-run-backup` du helper ; `shuttle run <op> --skip-backup` saute le dump de
facon explicite et inscrite dans le plan signe.

## `shuttle init` ne pouvait pas generer une application interne

`shuttle init` ajoutait toujours un domaine, une route Caddy et une URL de
disponibilite. La configuration `expose: internal` les refuse, donc les
applications sans route publique exigeaient une edition manuelle. `init` accepte
maintenant `--expose internal`, genere le service principal et omet ces champs.
Sans cette option, ou avec `--expose public`, la configuration conserve les
meme valeurs et le meme format qu'avant.

## Les pins d'infrastructure redevenaient obsoletes

`shuttle setup` signalait que les pins de Redis, RabbitMQ, Caddy et du registre
ne correspondaient plus aux canaux stables : Redis avait depasse 8.10.1,
RabbitMQ etait passe a 4.4.0 et les index de Caddy et du registre avaient ete
reconstruits. Le refresh manuel repart maintenant des digests d'index exposes
par la meme commande Buildx que le controle d'installation, lit les versions
declarees par les images et valide les quatre canaux avant toute ecriture. Un
changement majeur ou un downgrade interrompt le refresh ; RabbitMQ 4.4 demande
qu'un noeud deja passe depuis une ancienne mineure active tous ses feature flags
avec `rabbitmqctl enable_feature_flag all` avant le prochain deploy, sinon il
peut refuser de demarrer en 4.4. Les images
deja retenues sur les hotes existants ne changent pas, et le helper continue
d'accepter une version plus recente dans la meme majeure.

## `shuttle init` generait encore Caddy 2.10.2

Le refresh des pins vers Caddy 2.11.7 n'avait touche que le defaut de `setup`.
Le generateur de configuration ecrivait toujours son propre digest, celui de
Caddy 2.10.2 (CVE-2026-27585 et CVE-2026-27589, corrigees en 2.11.1), et tous
les projets crees depuis portaient ce pin dans `caddy.image`.

Le generateur reprend maintenant le defaut de `setup`, qui passe au rebuild du
22-10-2026 de Caddy 2.11.7 (magasin de certificats sans la racine emSign
ECC Root CA - G3, CVE-2026-113470).

## Un Redis retenu ne pouvait recevoir aucun correctif de securite

Une application gardee sur Redis 7.4.5 par `production.redis_image` ne pouvait
pas passer en 7.4.11, qui corrige CVE-2026-25243 et CVE-2026-81934. Le helper
root n'acceptait que le pin de la release (Redis 8.10.1 depuis v0.0.41) ou
l'image exacte deja en service : le deploiement d'Demo-app a echoue sur
"redis infrastructure image does not match the pinned runtime", puis, avec le
pin de la release, sur "redis major change 7 -> 8 requires an explicit data
migration". Il ne restait que l'image vulnerable.

Le helper accepte maintenant une version plus recente de l'image retenue dans
la meme majeure : une image officielle `redis` (ou `rabbitmq`) epinglee par
digest, dont la version declaree par l'image elle-meme (`REDIS_VERSION`,
`RABBITMQ_VERSION`, lue apres le pull) a la meme majeure que celle en service et
ne lui est pas inferieure. Le tag n'est pas cru : une reference etiquetee 7.4
dont le digest est Redis 8 est refusee comme tout changement de majeure. Un
changement de majeure, un retour en arriere, une pre-release, un autre registre
ou une reference sans digest restent refuses ; une premiere installation prend
toujours le pin de la release. Les configurations qui gardent l'image retenue
ou le pin de la release se deploient exactement comme avant.

Le workflow de release suit maintenant `CI_RUNNER` comme la CI, pour qu'un tag
produise encore des fichiers signes quand les runners heberges de GitHub sont
indisponibles.

## Un deploiement env-only ou secret-only annule pouvait etre annonce comme reussi

Un deploiement env-only ou secret-only en echec etait annonce comme reussi
pendant que Swarm le restaurait, car l'ancienne et la nouvelle release
portaient la meme image. Sur Docker 29.9.2, la mesure a montre 13 secondes en
`updating`, 1 en `rollback_started` avec deux taches voulues, puis 4 secondes
avec l'ancienne tache seule et `rollback_started`, avant 27 secondes en
`rollback_completed`.

La convergence consulte maintenant UpdateStatus depuis le debut du deploiement
et refuse une release des que le rollback est signale. Elle ne demande pas
`completed`, ce qui ajouterait les 10 secondes de surveillance Swarm a chaque
promotion et ferait depasser les petits SLO. Les redeploiements identiques, les
changements d'image et les statuts obsoletes restent compatibles.

## Les jobs CI etaient ignores depuis une branche de fonctionnalite

Depuis une branche autre que `main` ou `develop`, les filtres du workflow
ecartaient les trois jobs : `ci-local` annoncait pourtant un pipeline passe en
581 ms. Lorsque les jobs etaient forces, l'image par defaut `golang:1.23`
echouait car le module exige Go 1.27. Le tag 1.27.2 echouait ensuite sur
GO-2026-6809, corrige par le toolchain 1.27.3 du module.

Le script force maintenant les jobs et derive les images Ubuntu et macOS du
toolchain (ou de la directive Go en son absence). Un resume sans job `ci/`
execute est un echec. Les options supplementaires restent transmises apres les
valeurs par defaut et peuvent toujours les remplacer.

## Les deploiements peuvent preparer leurs secrets avec Hashvault

Un `stack deploy` reapplique les references du compose et annule celles ajoutees
hors deploiement. Le backend `secrets.backend: hashvault` fait preparer les
objets Swarm avant la promotion, par le helper signe sur le manager. Seul le
manifeste et ses references voyagent : aucune valeur ne revient au poste.

La stack conserve les versions, cibles de fichiers et proprietaires declares
dans `hashvault.json`, remplace les anciens montages correspondants et retient
le descripteur pour le rollback. Apres convergence, le helper confirme la release
observee dans le coffre. Un descripteur exporte permet de redeployer pendant
que le coffre est scelle ; une confirmation differee se reprend avec
`shuttle secrets sync`, apres une nouvelle verification de sante.

La confirmation attend que chaque service ait ses replicas en etat Running sur
l'image appliquee, et que chacune de ces taches monte exactement les secrets de
la stack signee (objet, cible, proprietaire, mode). Elle dispose de 45 s pendant
la promotion, comptees dans le delai de la session SSH, et de 3 min 30 dans
`shuttle secrets sync`. Une rotation ou
un rollback garde souvent les memes images : l'attente de convergence passait
alors sur les anciennes taches, et le coffre aurait enregistre une publication
qu'aucun conteneur ne lisait encore. Le manifeste signe est celui commite a
`HEAD` ; un `hashvault.json` non suivi ou modifie est refuse avant le build.

Un `shuttle secrets sync` qui ne peut pas encore confirmer (coffre scelle ou
injoignable, taches encore en cours de remplacement) le dit et sort en erreur,
mais termine son operation proprement : il ne laisse plus de verrou
`recovery_required` qui bloquait ensuite tout deploiement, rollback ou sync de
l'application. Une release sans preparation Hashvault est signalee comme telle,
jamais comme confirmee. Une vraie panne (stack illisible, convergence en echec,
enrolement casse) reste un echec, et `shuttle operations recover` la libere en
observant seulement, puisqu'un sync ne touche ni la stack, ni le registre, ni
l'edge.

Les backends existants gardent leur comportement et leur format de configuration.
La cle machine reste sur le manager, dans une configuration root privee. Le
nouveau contrat est couvert par des tests de configuration, signature, montages
et permissions ; voir `docs/hashvault.md` pour l'enrolement et les limites.

## Un deploiement annule par la sonde de disponibilite se recupere

Quand la sonde de disponibilite echoue, le deploiement restaure la release
precedente : `current.yml` redevient l'ancienne release et le manifeste que
l'operation a ecrit et journalise passe dans `previous.yml`. La recuperation ne
reconnaissait ce manifeste propre a l'operation que dans le slot `current`, et
refusait donc tout (`unknown retained previous artifact is not authorized`) :
l'application restait bloquee en `recovery_required`, et aucun deploiement
suivant ne pouvait reserver l'operation (preprod demo-core, 19-10-2026).

Le digest exact journalise par l'operation est maintenant reconnu dans les deux
slots. Il n'est jamais selectionne : la recuperation converge toujours sur la
release que le rollback a restauree.

## `shuttle logs` lit chaque tache separement

La cause du blocage est confirmee sur l'hote de production (Docker 29.7.2,
19-10-2026) : `docker service logs <service>` ecrit toutes ses lignes puis ne
ferme jamais le flux des que le service a plusieurs taches dans son historique,
meme a `--tail 100`. Le meme appel cible sur une tache (`docker service logs
<task-id>`) rend la main immediatement, et `docker logs` aussi.

Le helper liste les taches (`docker service ps --quiet`), puis lit chacune avec
`--tail`, de la plus ancienne a la plus recente, sous un plafond de 3 MiB
(sous les 4 MiB du transport SSH, contre 1 MiB avant) et le meme delai de
15 secondes. La sortie garde la semantique precedente (une
queue par tache, tache en cours en dernier). Un identifiant de tache inattendu
est refuse avant toute lecture. Le helper installe sur un hote doit etre mis a
jour (`shuttle helper update`) pour en beneficier.

## Les gros volumes de logs finissaient en timeout SSH opaque

Sur un service avec deux taches dans l'historique, `shuttle logs --lines 100`
rendait 401 lignes en une seconde, mais 300 lignes demandees finissaient au
timeout SSH de 120 secondes. Le helper collectait la sortie Docker sans limite
de taille ni delai propre. Le code ne confirme pas un interblocage de pipe :
les deux flux sont deja draines, y compris au-dela du plafond cote SSH.

La collecte est maintenant bornee a 1 MiB cumule : le depassement arrete Docker
et demande explicitement de reduire `--lines`, sans renvoyer de logs partiels.
Un delai de diagnostic de 15 secondes signale une collecte Docker bloquee avant
le timeout du transport. Ce delai borne le symptome ; il ne prouve ni ne corrige
la cause d'un blocage interne a Docker sur l'hote observe. Des tests locaux
couvrent les deux flux au-dela de la capacite des pipes et un producteur qui
ne s'arrete pas apres depassement. Aucun acces a l'hote de production.

`--lines` est valide avant de lire la configuration, entre 1 et 1000, avec une
erreur claire et sans afficher l'aide complete. Le defaut de 100 et la semantique
Docker par flux de chaque tache restent inchanges ; le plafond de taille
s'applique a tous les environnements utilisant le helper signe.

## Un dockerfile relatif se lit depuis son contexte de build

Compose lit un `dockerfile` relatif depuis le `context` du service, alors que
`docker build -f` le lit depuis le dossier courant. Une app de monorepo avec
`context: ../..` et `dockerfile: apps/web/Dockerfile` echouait donc avec
`resolve : lstat apps` avant tout build. Le chemin est maintenant resolu contre le
contexte, comme le fait Compose. Un chemin qui n'existe que relativement au
dossier courant reste accepte, pour les configurations existantes.

## make install ne garde plus de shuttle.previous

Une seule version de `shuttle` est installee : `make install` remplace le binaire
du PATH et supprime le `shuttle.previous` laisse par les versions precedentes du
script. Une generation conservee derive des sources et finit executee par erreur.
Pour revenir en arriere, relancer `make install` depuis le commit precedent.

## existing-stack : deploiement plus rapide et sans coupure inutile

Sur Ploydok staging, un deploiement prenait 11 min 40, dont 6 min 50 de
nettoyage des anciennes releases (environ 2 300 commandes SSH + sudo), et
coupait le trafic 9 s a chaque fois parce que l'image Caddy changeait meme
sans modification.

- Le nettoyage lit l'etat Docker de l'hote une fois, puis le relit seulement
  juste avant chaque suppression de manifeste, et resout les images en un seul
  appel. Les memes protections s'appliquent.
- Le builder `shuttle-<app>-existing` est conserve entre deux executions :
  les couches inchangees viennent du cache. Le cache est plafonne par
  `retention.build_cache` (20GB par defaut) et deux executions d'une meme app
  ne tournent plus en parallele sur le poste.
- Une image identique a celle qui tourne (couches, configuration, plateforme)
  n'est plus transferee : son digest est conserve et Swarm ne redemarre pas le
  service.

## Les anciennes releases existing-stack remplissaient le disque

Le mode `shuttle deploy existing-stack` creait un tag neuf a chaque execution,
sans retirer les releases precedentes. Sur Ploydok staging, 26 releases ont
laisse 28,29 Go d'images (19,49 Go recuperables) et 5,426 Go dans le registre ;
la partition racine a atteint 100 %.

Apres succes de la commande apply et verification de tous les digests,
`retention.keep_releases` conserve une release par defaut (minimum 1). Les tags
plus anciens des seuls depots construits sont retires du Docker de l'hote et
leurs manifestes supprimes du registre. Les references des services, taches et
conteneurs actifs restent protegees, meme anciennes. Le rollback appartient a
apply et se termine avant ce nettoyage ; augmenter la retention permet de garder
un historique pour un rollback ulterieur. Aucun prune global ne tourne.

Les echecs de nettoyage et le refus de suppression du registre sont des
avertissements, sans echec du deploiement verifie. L'espace libere et l'occupation
avant/apres sont affiches. La collecte des blobs reste une operation hors ligne
du registre gere par la plateforme. Les configurations existantes utilisent la
valeur par defaut sans nouvelle cle obligatoire. Voir `docs/existing-stack.md`.

## Mettre a jour une stack existante sans remplacer son architecture

Ploydok utilise deja un Swarm mono-noeud avec son propre agent, son registre,
ses montages et son protocole de mise a jour. Le mode gere de Shuttle refuse
ces montages ; le mode Compose aurait cree une autre architecture.

`shuttle deploy existing-stack` construit et transfere les images vers un hote
SSH epingle, verifie leur identite, les publie dans le registre loopback deja
present et remet un manifeste par digest a la commande de mise a jour declaree.
La plateforme reste responsable des sauvegardes, migrations, controles de sante
et rollbacks. Les images locales et le builder de cette execution sont nettoyes.
Le helper signe, les installations PostgreSQL et les commandes de deploiement
existantes ne changent pas. Voir `docs/existing-stack.md`.

## Une PWA derriere `basic_auth` ne redemande plus le mot de passe en boucle

Le 2026-10-15, la preprod HDV (Next.js PWA derriere `caddy.basic_auth`)
redemandait le mot de passe sans fin. Avec les bons identifiants, les pages
repondaient 200, mais deux requetes partaient toujours sans identifiants : le
manifeste (`/manifest.webmanifest`, que le navigateur charge sans credentials)
et le precache du service worker (`fetch("/offline", { credentials: "omit" })`
puis les assets `/_next/static/*`). Caddy leur repondait `401` avec un defi
`WWW-Authenticate: Basic`, et Safari affiche une nouvelle demande pour chacune.

- `caddy.basic_auth.public_paths` liste les chemins servis sans le gate. Le
  helper ecrit un matcher nomme dans le gate lui-meme
  (`@shuttle_gated not path ...` puis `basic_auth @shuttle_gated`), de sorte
  qu'une host route qui importe le gate recoit les memes exemptions.
- Les chemins sont valides deux fois (CLI et helper) avec le matcher etroit
  des path routes ; `/` et `/*` sont refuses, comme une liste sans
  utilisateurs, une traversee `..` ou un doublon. Au plus 16 chemins.
- Une config qui declare la liste exige la capacite helper
  `caddy-basic-auth-public-paths` : un helper plus ancien ignorerait le label
  et garderait tout derriere le gate, ce qui est sur mais laisse la boucle.
- Sans `public_paths`, le bloc rendu est identique a avant.

## La recuperation n'est plus refusee sur un hote qui porte plusieurs clusters PostgreSQL

Le 2026-10-15, un deploiement preprod HDV a echoue au build et l'operation est
restee `recovery_required`. La recuperation (helper v0.0.38) refusait avec
`missing recovery proof: configured native PostgreSQL version and cluster are
not present on the host`, alors que `pg_lsclusters` montrait `18/main` et
`18/preprod` en ligne. La baseline des writers enregistre tous les clusters en
listes separees par des virgules (`18,18` et `main,preprod`), mais
`observePostgres` collait ces listes brutes en un seul chemin,
`/etc/postgresql/18,18/main,preprod`, qui n'existe jamais. Tout hote a deux
clusters ne pouvait donc plus etre recupere, et chaque deploiement de la cible
restait bloque derriere l'operation.

- `observePostgres` lit les deux listes paire par paire et exige que chaque
  cluster enregistre soit encore present ; des listes de longueurs differentes
  ou un element vide restent refuses comme non configures.
- La baseline trie desormais les paires (version, cluster) ensemble au lieu de
  trier chaque liste a part, ce qui pouvait apparier une majeure 16 au cluster
  d'une 18. Une baseline ancienne reste lisible : avec des majeures egales
  l'appariement par index est exact, et un appariement faux ne peut qu'echouer
  ferme.
- Un hote a un seul cluster produit la meme baseline et le meme chemin
  qu'avant.

## Une operation a recuperer ne bloque plus `helper update`, ni la recuperation un registre installe par un Shuttle anterieur

Le 2026-10-15, un deploiement preprod refuse par le garde memoire est reste
`recovery_required`. Le helper root de la VM etait en v0.0.20 : sa recuperation
verifiait la route Caddy avec `caddy config`, une commande qui n'existe pas
(corrigee depuis longtemps dans les sources). Chaque recuperation echouait, et
`shuttle helper update` etait refuse parce que ce meme deploiement attendait
une recuperation : la reservation `helper-update` est globale et
`operations.conflict` la bloquait sur tout enregistrement `recovery_required`,
puis la migration du helper (journal et inventaire des writers) refusait a son
tour. Seul un binaire copie a la main sur l'hote a casse la boucle.

- Une reservation `helper-update` attend toujours une operation vivante (bail
  actif), mais plus une operation `recovery_required` : celle-ci n'a plus
  d'executeur, et remplacer le helper est justement le remede quand c'est lui
  qui ne sait pas recuperer. La migration admet un tel enregistrement s'il est
  coherent (`state` et `recovery_required` d'accord) ; ses writers doivent
  toujours etre fermes (sinon `shuttle operations writers <id>` d'abord), les
  processus de l'ancien helper sont toujours draines avant la fin, et
  l'enregistrement reste `recovery_required` pour le nouveau helper. Les autres
  operations globales (backup, reboot...) attendent toujours la recuperation.
- La recuperation passee ensuite avec un helper v0.0.37 a echoue sur `missing
  recovery proof: registry image identity is unsafe` : le registre tournait en
  `registry:3.1.1`, pose par un Shuttle anterieur, et seul le pin courant 3.1.2
  etait admis. Ni `setup` ni un deploiement ne recreent un registre existant
  pour changer de pin, et seul un deploiement liberable par cette recuperation
  aurait pu le faire evoluer. Les pins precedents sont maintenant listes
  (`rootRegistryPreviousImages`, digests exacts) et la recuperation accepte un
  conteneur qui en porte un s'il a l'etiquette `dev.shuttle.owner=system` ; la
  liaison loopback, `restart: always` et la sante restent exigees. La
  recuperation restaure l'existant, elle ne monte pas le registre de version.
  Aucun autre controle de la recuperation ne compare l'hote a un pin compile.

Ces deux corrections agissent depuis le helper installe : un hote dont le helper
est anterieur a cette version reste soumis aux anciennes regles jusqu'a sa
premiere mise a jour.

## Un garde memoire qui avertit n'ecrit plus « deployment refused »

En `--memory-budget=warn` (Swarm) et en strategie Compose, l'alerte reprenait
le texte du refus : `⚠ deployment refused: the rolling update needs 2.25 GiB
... continuing because --memory-budget=warn`, dans un deploiement qui a
continue et reussi (Demo-app, 2026-10-15). L'alerte s'ouvre maintenant sur
`Memory budget exceeded` suivi des memes chiffres ; seul le refus de `strict`
garde `deployment refused`.

## `deploy --memory-budget=warn`, et le garde memoire ne compte plus les services stop-first

Le 2026-10-15, `shuttle deploy` d'Demo-app a refuse avant tout build :
`the rolling update needs 2.25 GiB of free memory (agents-api 512 MiB,
agents-worker 512 MiB, api 512 MiB, redis 256 MiB, web 512 MiB), host has
1.09 GiB available of 2.97 GiB`. Les quatre services applicatifs occupaient
alors environ 420 MiB au total. Le garde additionne des plafonds, pas des
tailles residentes : sur un hote de 3 GiB il exige 75 % de la RAM libre.

- Le garde Swarm ne compte plus les services `update_order: stop-first` : leur
  ancienne tache s'arrete avant que la nouvelle demarre, il n'y a jamais deux
  copies. Compose garde la liste complete, comme plafond que l'hote doit tenir.
- `shuttle deploy --memory-budget=warn` signale un depassement du plafond de
  chevauchement et deploie quand meme. `strict` reste le defaut. Une
  configuration illisible ou un `/proc/meminfo` illisible restent des erreurs
  dans les deux modes : `warn` accepte un surengagement visible, pas un garde
  qui n'a rien mesure.
- Pas de serialisation des services : `docker stack deploy` n'en offre pas, et
  l'orchestrer dans le helper root compliquerait prune, echecs partiels et
  rollback. Pas de seuil automatique non plus : le choix reste a l'operateur.

## L'edge ne publie plus `Via: 1.1 Caddy`

Le `reverse_proxy` de Caddy ajoute `Via: 1.1 Caddy` a chaque reponse proxifiee :
signale le 2026-10-12 dans l'onglet reseau d'example.com, l'en-tete annonce le
proxy et le protocole devant l'application sans servir aucun client. Le snippet
`shuttle_security` le supprime (`header -Via`). Une suppression est differee par
Caddy, elle retire donc aussi l'en-tete ajoute apres la reponse de l'amont ;
verifie avec caddy v2.11.7, les autres en-tetes inchanges. La preuve de route
d'`origin.go` ne lit pas `Via`.

## Pins Caddy et registre rafraichis : caddy v2.11.7, registry 3.1.2

Les digests embarques pour l'edge Caddy et le registre en boucle locale
n'etaient plus ceux de `caddy:latest` et `registry:latest` : la mise a jour de
l'edge de production du 2026-10-12 l'a signale par deux `WARNING`. Les pins
passent a `caddy@sha256:f2a1290d...` (v2.11.7, la version sur laquelle le
nouveau comportement des en-tetes de `shuttle_security` a ete verifie) et a
`registry:3.1.2@sha256:ddf75434...`. Meme majeure dans les deux cas. Les pins
Redis et RabbitMQ ne changent pas ici : une montee de version d'un service a
donnees demande sa propre verification.

## Une image d'infrastructure epinglee mais plus recente que `latest` avertit au lieu de refuser

`setup` et `deploy` refusaient d'installer Caddy, Redis, RabbitMQ ou le registre
des que le digest epingle dans le binaire n'etait plus celui du tag stable sur
Docker Hub. Le 2026-10-12, ce refus a bloque une mise a jour urgente de l'edge
de production : le digest relu restait une release officielle et signee, seul
Docker Hub avait publie plus recent. Decision de l'operateur : c'est une alerte,
pas une barriere. La commande affiche un `WARNING` qui nomme le canal et le pin
installe, et continue avec le pin relu. Un tag stable impossible a resoudre est
traite de meme. Rafraichir les pins reste une tache de release.

## `setup --adopt --cutover-edge` met a jour l'edge Shuttle deja en place

Sur un hote dont 80/443 sont tenus par l'edge Shuttle lui-meme, le releve
d'adoption rapporte le conteneur `shuttle-edge_caddy` et, a cote, les processus
`docker-proxy` qui publient ses ports. Le conteneur etait bien ignore (le
redeployer est le chemin idempotent), mais `docker-proxy` etait lu comme un
ecouteur etranger impossible a restaurer, et `--cutover-edge` refusait. Constate
le 2026-10-12 sur la production demo, ce refus empechait d'appliquer le
nouveau snippet `shuttle_security`.

Un `docker-proxy` sur un port qu'un conteneur publie aussi est desormais compte
comme la publication de ce conteneur. Un `docker-proxy` seul, sans conteneur
publie sur son port, reste refuse comme avant.

## Un redemarrage en attente n'empeche plus `setup --adopt`, il est signale

`shuttle setup --adopt --yes` refusait de demarrer des que l'hote portait
`/var/run/reboot-required`. Sur la production demo, le marqueur datait d'une
mise a jour du noyau par unattended-upgrades, cinq semaines plus tot, et le
refus a bloque le 2026-10-12 une simple mise a jour de l'edge Caddy. Le garde ne
protegeait rien : une adoption ne redemarre jamais sans `--allow-reboot`, et
chaque stage est protege par son checkpoint.

Decision de l'operateur : un redemarrage en attente est une alerte, pas une
barriere. La commande affiche un `WARNING` qui nomme l'hote et le flag, puis
continue sans redemarrer. `--allow-reboot` garde exactement son sens : laisser
le run prendre le redemarrage. La ligne `pending reboot` du plan dit desormais
« warning only ».

## L'edge ne remplace plus les en-tetes de securite que l'application envoie

Le snippet `shuttle_security` posait `X-Content-Type-Options`,
`Referrer-Policy` et `X-Frame-Options` sans condition. Caddy ecrasait donc la
valeur de l'application : mesure le 2026-10-12 sur example.com, pro et bo, qui
envoient `X-Frame-Options: DENY` et `Referrer-Policy: no-referrer` sur leurs
routes portant un jeton, le visiteur recevait `SAMEORIGIN` et
`strict-origin-when-cross-origin`. Une application ne pouvait pas se proteger
plus que l'edge.

Ces trois en-tetes deviennent des valeurs par defaut (`header ?Champ`) : ils ne
sont ecrits que si l'application ne les envoie pas. HSTS reste pose sans
condition, c'est une propriete du domaine. Chaque defaut a sa propre directive
`header` : dans un meme bloc, Caddy regroupe les champs `?` en une seule
condition, vraie seulement si aucun n'existe, si bien qu'une application qui
envoyait `X-Frame-Options` perdait aussi le `nosniff` par defaut (reproduit
avec caddy v2.11.7). Une application qui n'envoie rien garde exactement la
protection d'avant, et la preuve de route d'`origin.go` voit toujours ces
en-tetes. Le contenu du Caddyfile change, donc le nom de sa config Swarm :
le prochain `shuttle setup` met l'edge a jour.

## Les binaires sont construits avec Go 1.27.2, sans les failles de la stdlib 1.27.0

Le gate de `scripts/release.sh` a refuse la release le 2026-10-10 :
`govulncheck` trouvait neuf vulnerabilites appelees par notre code dans la
stdlib de Go 1.27.0 (net/http, http2, crypto/tls, net/textproto, os), toutes
corrigees en 1.27.2. Les workflows epinglaient `go-version: '1.27.0'`, donc la
CI aurait publie des binaires vulnerables. Ils prennent maintenant la derniere
Go stable (`go-version: stable`), et `go.mod` declare `toolchain go1.27.2` pour
que `release.sh` et `make install` sur un poste encore en 1.27.0 telechargent
la toolchain corrigee au lieu d'echouer. Le langage reste `go 1.27`.

## Un deploy rate sans rien promouvoir ne bloque plus le deploy suivant

Chaque echec de `shuttle deploy` termine sa reservation en
`operation-abort`, donc en `recovery_required`, y compris quand il meurt
dans le build local de l'image avant toute promotion. Le deploy suivant de
la meme application etait alors refuse d'emblee avec `operation ... requires
recovery for deploy (target demo-console, ...); waited 0s`. Mesure dans le
journal de 198.51.100.31 : une dizaine de deploys de demo-console en
`recovered` entre le 2026-10-06 et le 2026-10-10, chaque fois par le meme
geste manuel (`operations recover --dry-run`, lecture de « tasks match
retained current digests », puis `--yes --plan-digest`) pour un plan qui
n'avait rien a faire (`completed: none`).

Le deploy joue maintenant ce geste lui-meme, et seulement lui : quand la
reservation est refusee par un deploy non recupere de la MEME application,
il demande le plan au helper et ne l'applique que si l'observation est
`safe`, sans preuve manquante ni element non resolu, et sans aucune action
derivee (`observed.actions` vide). L'application est liee au digest observe,
que le helper re-observe sous son verrou avant de clore l'enregistrement.
Une autre application, un `helper-update`, une operation VPS ou un plan qui
toucherait l'hote restent a l'operateur : le deploy s'arrete et nomme la
commande `shuttle operations recover <id> --dry-run`. Cote helper rien ne
change ; il suffit de mettre a jour le CLI.

## Le superviseur d'un runner de build ne s'arrete plus sur un heartbeat lu a moitie

La CI de `main` a echoue le 2026-10-08 sur
`TestRunnerSupervisorCleansItsLeaseAfterControlDisconnect` (`exit status
124`), alors que le meme commit passait sur `develop` et sur macOS. Le
superviseur ecrivait le heartbeat en place (`printf ... > heartbeat`), et sa
boucle de surveillance relit ce fichier chaque seconde depuis un autre
processus. `>` vide le fichier avant d'ecrire : une lecture tombee entre les
deux voyait une valeur vide et terminait le superviseur en `exit 124`, comme
si le client s'etait tu. Sur un runner, c'est un build en cours qui est
arrete. Mesure sous `dash` : 20 lectures vides sur 3848 en ecriture en place,
0 sur 4852 avec un renommage.

Le heartbeat est maintenant ecrit dans `heartbeat.next` puis renomme, ce qui
est atomique dans un meme repertoire. Rien ne change cote configuration ni
cote protocole ; le correctif vit dans la commande envoyee au runner par le
CLI, donc il suffit de mettre a jour le CLI.

## Une note d'operateur dans le journal ne bloque plus `shuttle helper update`

Mesure le 2026-10-08 sur l'hote de demo-console (198.51.100.31) : chaque
`shuttle helper update` signe echouait avant tout remplacement avec
`read operation writer proof: json: unknown field "note"`, et laissait une
reservation `helper-update` en `recovery_required` qui bloquait l'hote. Trois
tentatives de septembre avaient deja fini closes a la main. La cause etait
un enregistrement de deploy clos a la main le 2026-09-15, avec un champ
`note` ajoute sur un evenement. Le coordinateur lit ce fichier sans
probleme, mais la verification prealable de la mise a jour relit tout le
journal en mode strict et le refusait, quelle que soit la version du helper
installe (reproduit avec v0.0.27).

`Event.note` est maintenant declare. Shuttle n'en ecrit jamais : le champ
existe pour que les lecteurs stricts acceptent une annotation d'operateur,
comme `note` sur l'etat des writers depuis septembre. Tout autre champ
inconnu reste refuse. Rejoue sur les 45 enregistrements reels de l'hote : tous
passent. Un hote dont le helper installe porte deja le defaut ne peut pas se
mettre a jour par le chemin signe : il faut une installation root unique du
nouveau binaire, puis `shuttle helper update` refonctionne.

## Un balayage du registre rate apres la promotion ne bloque plus l'application

Mesure le 2026-10-08 sur `web` (operation `3231ee16`) : `stack-apply`
avait converge, la route etait chargee, `web_web` tournait 1/1 sur
l'image de `current.yml`. Puis un seul `DELETE` d'un manifeste perime du
registre local a recu `connection reset by peer`. La phase a echoue comme
n'importe quelle panne, l'operation est passee `recovery_required`, et chaque
`shuttle deploy` suivant etait refuse aussitot. `operations recover` ne
pouvait pas la clore non plus : son plan voulait redeployer la release
d'avant, puis refusait avec `unknown retained current artifact is not
authorized`, parce que le `current.yml` ecrit par l'operation n'etait pas dans
son baseline. `api` avait deja ete clos a la main le 2026-10-05 pour la
meme raison ; `web` aussi.

Deux corrections, une par cause.

Le balayage qui suit une promotion (manifestes du registre, collecteur, cap du
cache, images locales) est du menage : chaque passage recalcule son plan a
partir des stacks retenues et supprime les memes restes. Son echec termine
donc la phase avec un avertissement (`warning` dans la phase du journal,
`shuttle-root warning:` affiche par le CLI) au lieu de l'echouer, comme le
report du collecteur quand une autre operation est active. La ligne est
tracee dans `sweepAfterRootPromotion` : le seul echec qui exige encore la
recovery est un registre que le collecteur a arrete sans pouvoir prouver
qu'il est reparti, car chaque pull suivant echouerait. La convergence Swarm
n'en fait pas partie : elle est prouvee avant le balayage, et une stack qui ne
converge pas echoue sa phase comme avant.

Le balayage qui precede un deploiement (`stack-reclaim`, sous l'operation du
deploy) suit la meme regle : une image que le daemon refuse de retirer, une
liste trop lente ou le verrou partage trop long termine la phase avec un
avertissement, car il laisse l'hote comme il l'a trouve. Le CLI l'affiche, et
seuls l'identite et les controles avant le balayage echouent encore.

`stack-apply` journalise maintenant le digest complet du `current.yml` qu'il
va ecrire (`current_manifest_sha256`), avant le fichier, et ne l'ecrit pas si
le journal echoue. La recovery d'un `deploy` accepte un `current.yml` dont le
digest est exactement celui que cette operation a journalise, le selectionne
comme cible, compare les taches en service a ses digests et ne le redeploie
que s'ils different. Un `current.yml` non journalise, ou journalise avec un
autre digest, reste inconnu et refuse : la regle fail-closed ne change pas.

Compatibilite : les deux champs sont optionnels (`omitempty`), les anciens
enregistrements se lisent et se recuperent comme avant, et un ancien helper
ignore les nouveaux champs. Les deux corrections vivent dans le helper :
elles ne s'appliquent sur un VPS qu'apres `shuttle helper update`, a lancer
hors de toute operation active. Le protocole signe ne change pas.

## Un nettoyage de cache de build rate sur le poste ne bloque plus les deploiements suivants

Apres une promotion verifiee, le client lance `docker buildx prune` sur la
machine de l'operateur. Cette commande ne touche rien sur le VPS. Quand elle
echouait (demon Docker redemarre, builder deja supprime), `shuttle deploy`
marquait le nettoyage comme echoue et terminait l'operation par un abandon :
le journal d'operations de l'hote passait en `recovery_required`, et chaque
deploiement suivant de l'application etait refuse avec "requires recovery
for deploy" jusqu'a ce qu'on edite a la main `/var/lib/shuttle/operations`.

Un cache local qui ne se vide pas ne dit rien sur la release, qui est deja
promue et verifiee. L'echec devient un avertissement qui donne la commande
pour recuperer l'espace (`docker buildx prune --builder shuttle-<app>`), et
le deploiement se termine en succes. Le mode compose, qui n'utilise pas le
journal, suit la meme regle. Les echecs des ecrivains (tunnel du registre,
builder distant, fermeture des ecritures) gardent leur comportement : eux
peuvent encore toucher l'hote, donc ils abandonnent toujours l'operation.
Rien ne change dans la configuration.

## Un build Next.js ne televerse plus a chaque deploiement un cache que personne ne relit

Le build Swarm exporte son cache vers le registre du VPS en `mode=max`, pour
qu'un etage de dependances compile reste restaurable apres une eviction du
cache local. Sur un Dockerfile Next.js, l'etage intermediaire commence par
`COPY . .` puis `next build` : il change a chaque commit, et son export
(`node_modules`, `.next`) n'est jamais relu. Mesure sur web : 114 s
d'export par deploiement, dont 86 s a compresser cet etage et 28 s a
l'envoyer dans le tunnel, sur un build de 4 min 13.

`deploy.build_cache_mode` choisit le mode de cet export : `max` (le defaut,
y compris quand le champ est absent) ou `min`, qui n'exporte que les couches
de l'image finale. Avec `min` sur le meme projet, l'export tombe a 3 s et le
deploiement complet passe de 5 min 10 a 2 min 06 (avec un cache de
compilation conserve cote Dockerfile). Les couches de l'image partent
toujours avec l'export, donc le push qui suit reste instantane.

Rien ne change pour une configuration qui ne nomme pas le champ : elle se
charge a l'identique et exporte toujours en `mode=max`. Une valeur autre que
`max` ou `min` est refusee a la validation.

## Un VPS dont le reseau est sous 1500 de MTU ne perd plus les gros paquets des conteneurs

Docker cree `docker_gwbridge` a 1500. Sur Google Cloud (1460), un cloud
VXLAN (1450) ou une VM dans Kubernetes (1400), l'interface de la route par
defaut ne porte pas une trame de 1500. Les taches Swarm et les ports en mode
host (le 80/443 de l'edge) sortent par ce bridge : la poignee de main TCP
passe, puis chaque segment plein est perdu. L'ordre ACME de Caddy reste
pendu et les appels sortants d'une application expirent, sans rien dans les
logs. FrankenDeploy a rencontre la meme panne sur `docker0`
(yoanbernabeu/frankendeploy#112).

`20-docker` lit le MTU de l'interface de la route par defaut et, s'il est
sous 1500, cree `docker_gwbridge` a ce MTU avant `swarm init`, avec les
options documentees par Docker. Un bridge deja present appartient a un
Swarm actif et le recreer impose de quitter le Swarm : setup n'y touche
pas, et le nouveau controle `doctor` `docker.gateway_mtu` signale l'ecart
avec la marche a suivre. A 1500 ou plus, ou si le MTU est illisible, rien
n'est cree. Le golden de `20-docker` change donc de texte, pas de
comportement sur un reseau a 1500.

## Un secret ignore par Git n'entre plus dans une image par le contexte de build

`.gitignore` et `.dockerignore` sont deux listes. Un `.env.local`, une cle
ou un dump SQL cache a Git part quand meme vers BuildKit si `.dockerignore`
ne le nomme pas, et un `COPY . .` le grave dans une couche poussee vers le
registre du VPS et gardee pour chaque rollback. Avec un builder distant, le
contexte traverse aussi SSH. FrankenDeploy a corrige la meme fuite en
n'envoyant que ce que Git suit (yoanbernabeu/frankendeploy#115).

Shuttle garde le contexte tel que Docker le definit, parce que des assets
generes et des fichiers vendored y vivent legitimement, et refuse le seul
cas jamais voulu : un fichier ignore par Git, dont le nom dit secret
(`.env*` hors modeles, `*.pem`, `*.key`, `*.p12`, `*.pfx`, cles SSH,
`*.sql`, `*.dump`), que `.dockerignore` laisse passer. Le refus nomme les
fichiers et la correction. Les fichiers suivis par Git (choix explicite,
deja audite par `doctor`), `node_modules` et `vendor`, et un contexte hors
Git ne sont pas concernes. Le `.dockerignore` genere par `init` exclut deja
`.env` et `.env.*` : un projet initialise par Shuttle n'est pas bloque.

## init declare APP_SECRET pour Symfony comme APP_KEY pour Laravel

Symfony demarre sans `APP_SECRET`, ce qui est pire qu'un refus : CSRF,
URLs signees, remember-me et limitation de login echouent plus tard, a la
premiere requete qui en a besoin. Laravel avait deja son `APP_KEY` declare
par `init`. Symfony n'avait rien, donc le deploy ne pouvait pas refuser
un secret que la configuration ne demandait pas.

`init --preset symfony` declare maintenant `APP_SECRET`, sur le backend
host, expose en variable d'environnement, comme Laravel, et le resume
indique de le creer dans le fichier du VPS. La resolution existante
refuse alors un deploy ou il manque. Les configurations existantes ne
changent pas.

## Chaque tag publie ses binaires signes dans une GitHub Release

Depuis le retrait du site, un tag ne produisait qu'un artefact de workflow,
qui expire et se recupere mal. Le workflow attache maintenant les memes
fichiers (binaires, `checksums.txt`, `latest.json` signe) a une GitHub
Release sur le tag, recuperable par `gh release download`. Le depot est
prive : ce n'est pas un canal public, et `shuttle update` n'a toujours pas
d'origine par defaut (SHU-13). Un tap Homebrew ou un script d'installation,
comme FrankenDeploy, demande des binaires telechargeables par tous, ce qui
reste une decision produit.

## Un poste qui redemarre ne bloque plus les deploiements d'une application

Un writer `client_origin` se clot par un fence pidfd sur la machine et dans
le boot qui l'ont lance. Si le poste redemarre avant que le CLI ait clos son
operation (capot ferme, crash, coupure), `operations writers` refusait :
`client origin machine or boot changed; refusing local PID fencing`.
L'operation restait `recovery_required` sans issue, et `conflict()` refusait
toute nouvelle reservation de l'application. Mesure le 2026-10-05 sur
`api` : un deploy du 03-10 avait fini `stack-apply` et converge, le
poste a redemarre, et chaque `make deploy` suivant etait refuse.

La fin d'un boot est une preuve plus forte qu'un fence : aucun processus
d'un boot precedent ne peut exister. Meme machine-id et boot different
produisent donc un recu sans membre observe
(`EndedBootLocalReceipt`), sans sonder ni signaler aucun PID, puisque ces
numeros designent desormais d'autres processus. Le hash de preuve est celui
qu'un fence pidfd aurait produit sur un groupe deja eteint : le helper du VPS
le verifie sans mise a jour. Une autre machine reste refusee.

Le residuel note ici le 2026-10-05 (`operations recover` d'un `deploy`
interrompu apres `stack-apply` bloque sur `unknown retained current artifact
is not authorized`) est corrige plus haut, dans l'entree "Un balayage du registre rate
apres la promotion ne bloque plus l'application".

## Shuttle passe sous Apache-2.0

Le CLI, le helper et les templates sont Apache-2.0, installables sans condition.
Le site de distribution est retire depuis le 2026-09-14.
ADR : `docs/adr/0001-apache-2.0.md`.

## Les .env de production ne doivent plus passer par le poste

Copier un `.env` de production sur un laptop pour que Shuttle le renvoie au
VPS d'ou il vient est un mouvement sans destination, et une copie de plus
d'ou il peut fuir (disque, agent, zip, journal CI). Le backend
`secrets.backend: host` existait deja. Il n'etait pas le chemin que `init`
ecrivait, et aucun agent n'avait d'instruction pour s'y tenir.

`shuttle init` ecrit maintenant ce backend des qu'une configuration generee
declare un secret applicatif (Laravel `APP_KEY`), avec
`secrets.host.env_file` a `/opt/<app>/.env` sur le serveur. Redis et RabbitMQ
restent generes sur l'hote. Un projet sans secret applicatif (Hono plus
Redis seulement) garde `backend: swarm`, parce que le backend host exige au
moins une cle applicative. `.env.example` decrit le schema et dit de ne pas
le copier en local pour un deploy. `.gitignore` ignore `.env` et `.env.*`.

Le skill `shuttle-host-env` est embarque dans le binaire. `shuttle --install
skills` et `shuttle skills install` le copient dans tous les harness locaux
(Claude, Grok, Cursor, Codex, OpenCode, Agents), au niveau utilisateur (tous
les projets du poste) et au niveau projet (les collegues). `init` l'installe
deja dans le checkout genere. Relancer l'install apres une mise a jour
rafraichit le texte.

Rien ne change pour une configuration existante qui ne nomme pas de backend :
`Load` continue de defaulter a `swarm`. `shuttle secrets set` reste le
chemin de ce store.

## Le site de vente et sa distribution sont retires

Le 14-09-2026, `releases.example.com` servait encore une image web du
15-08 qui retirait `key_id` et `signature` du manifeste public : `shuttle update`
refusait donc toute release signee. GitHub Actions ne demarrait plus aucun job,
faute de paiement, et la mise a niveau du site demandait sept migrations sur la
base de production, un nouveau secret injecte par le Caddy partage et une
decision sur la vente. Le site est retire plutot que maintenu a moitie.

Sont supprimes `web/`, `deploy/`, les scripts de deploiement, de sauvegarde, de
restauration et Stripe avec leurs contrats, les jobs CI `web` et `web-image`,
l'audit Bun et l'envoi des releases vers le VPS. Sur le serveur, le service, sa
base, ses secrets, ses images et le repertoire de releases ont ete effaces.

Le workflow de release passe toujours le gate Go, construit et signe les
binaires, et les garde comme artefact du workflow au lieu de les envoyer vers un
repertoire qui n'existe plus.

La CLI n'a plus d'origine de release par defaut. Garder l'adresse du site
retire faisait appeler un hote mort par la verification de mise a jour de
chaque commande, et `shuttle update` echouait sur une erreur de
reseau qui n'indiquait pas la vraie cause. Sans `SHUTTLE_SITE_URL`, la
verification en arriere-plan ne fait plus aucun appel, et `shuttle update`
s'arrete avec "no release distribution channel is
configured". Avec `SHUTTLE_SITE_URL`, le comportement signe et epingle sur
l'origine est inchange, et `shuttle update --recover` fonctionne toujours sans
origine.

## Deux applications du meme VPS ne pouvaient pas deployer en meme temps

Le 14-09-2026, `make deploy` de `api` a echoue en quelques secondes :
`operation ... is active for deploy (target web, age 49s); waited 0s`. Rien
n'etait casse. `web` deployait sur le meme noeud depuis 49 secondes, et un
deploy etait une operation globale du VPS, reservee avant le build et refusee
sans attente. Pire, le premigrate d'`api` avait deja migre la base : le
schema etait en avance sur le code jusqu'a la relance manuelle.

Deploy, rollback et run sont maintenant des operations d'application. Elles
excluent une operation globale et une autre mutation de la meme application,
rien d'autre. Backup, restore, GC du registry, cache-prune, mise a jour du
helper, reboot et destroy restent globaux. La phase d'une application tient
`/run/shuttle-root.app-<app>.lock` pendant son travail Docker et ne prend
`/run/shuttle-root.lock` que pour ecrire son journal : c'etait ce verrou, tenu
pendant tout `docker stack deploy`, qui aurait remis les promotions en file
meme avec une regle de conflit assouplie.

Ce que les applications partagent reste serialise sur
`/run/shuttle-shared.lock` : l'ecriture du fragment Caddy et le reload du bord,
les balayages du registry et du magasin d'images. Le GC du registry ne tourne
que si son operation est seule sur l'hote : il arrete le registry et supprime
tout blob qu'aucun manifest ne reference, c'est-a-dire aussi les couches qu'une
autre application est en train de pousser. Sinon il est differe et journalise,
sans echec ; les manifests perimes sont deja supprimes et la prochaine
promotion seule recupere leurs blobs. Une reprise est refusee tant qu'une autre
operation est vivante, parce qu'elle redemarre le registry.

Cote client, un conflit avec une operation vivante est attendu jusqu'a dix
minutes au lieu d'echouer ; un conflit avec une operation `recovery_required`
echoue tout de suite, avec un message distinct (`requires recovery for`),
puisque seule une reprise peut le lever.

Compatibilite : un journal ecrit par un ancien helper porte `scope: global` sur
ses deploys. Il reste lisible et un deploy legacy encore vivant continue
d'exclure tout le monde. Le changement n'agit qu'apres `shuttle helper update`
sur chaque VPS, a faire hors de toute operation active.

## Le binaire macOS ne compilait plus depuis le journal des opérations

`make install` sur un Mac échouait avec `undefined: jsonState`, puis
`undefined: reserveRootOperation`, et la même compilation darwin du workflow de
release aurait cassé. Les deux fonctions n'existaient que dans des fichiers
`//go:build linux`, alors que du code compilé partout les appelait. La CI ne
lance `go vet` et `go test` que sous Linux, donc rien ne l'a signalé.
`jsonState` est déplacée dans `store.go`, sans build tag, parce que les deux
implémentations de `writeStateAt` s'en servent. `reserveRootOperation` reçoit
sous macOS le même stub que les autres actions du helper root, qui refuse avec
« shuttle-root is supported only on Linux ». Le comportement sous Linux ne
change pas : `go vet ./...` passe pour darwin et pour `GOOS=linux`.

## Un VPS en panne ne se voyait qu'en relancant doctor a la main

Rien ne surveillait le VPS entre deux commandes : un service arrete, un disque
plein, une sauvegarde perimee ou un certificat proche de l'expiration restaient
silencieux. `monitoring.enabled` installe maintenant un timer systemd par
application (`shuttle monitoring install|remove`, idempotents) qui controle les
services Swarm, Docker, Caddy, le registry loopback, PostgreSQL natif, Redis et
RabbitMQ seulement s'ils sont configures, l'espace et les inodes des donnees,
des images, du cache et des sauvegardes, la fraicheur des sauvegardes, TLS et
les derives SSH, UFW, DOCKER-USER et fail2ban, en lecture seule. Les rapports
dates `shuttle.monitoring/v1` distinguent sain, degrade, indisponible et non
applicable ; un controle expire ou en timeout n'est jamais sain.

Les incidents et retablissements passent par un canal HTTPS explicite, avec
temporisation, deduplication, retries bornes et journal des echecs de livraison.
La recette a coupe le canal pendant une panne applicative : l'incident est reste
en attente puis a ete livre au retour du canal, et le retablissement une seule
fois. La sonde `shuttle monitoring external`, lancee depuis la VM 232, a detecte
la meme panne independamment du VPS. Une maintenance declaree est bornee a sept
jours et ne supprime pas l'historique ; une fenetre illisible n'est jamais
consideree comme levee. Aucun controle ne purge ni ne modifie une regle reseau :
les 203 fichiers de securite controles sont restes identiques. Le monitoring est
opt-in, une configuration sans la cle ne change rien.

La recette a aussi corrige deux faux diagnostics. Un fichier secret de webhook
sous `/etc/shuttle`, pourtant documente, etait refuse parce que son dossier
parent etait tenu a la regle des dossiers d'etat prives : le canal apparaissait
indisponible sans explication. Et un VPS voyait ses regles publiques 22/tcp,
80/tcp et 443/tcp signalees comme inattendues a chaque cycle, alors que doctor
ne les signalait pas : la configuration installee ne reprenait ni le port SSH ni
`access.allowed_public_tcp_ports` du projet, et le runtime n'a que cette copie.
Elle les reprend maintenant, et une valeur explicite sous `monitoring.security`
reste prioritaire.

## Deux commandes pouvaient muter le meme VPS et une reprise ne laissait aucune trace

Un deploy, un rollback, une sauvegarde, un nettoyage du registry, une mise a jour
du helper ou un reboot pouvaient se chevaucher, et un echec au milieu ne laissait
que le verrou libre. Chaque operation est maintenant reservee dans un journal
persistant `/var/lib/shuttle/operations` avec identifiant, phases, resultat et
actions de reprise, sans secret. La recette a lance pendant un deploy actif un
deploy d'une autre application, une mise a jour du helper, un reboot et un
rollback : tous ont ete refuses en nommant l'operation active, sa cible et son
age. Le GC du registry a tourne pendant ce deploy et le rollback suivant a
retrouve le digest precedent.

Une operation interrompue reste `recovery_required` meme verrou libre.
`shuttle operations writers` puis `shuttle operations recover` montrent l'etat
observe et les actions en simulation, et n'appliquent qu'avec le digest exact ;
un digest perime est refuse. La recette a repris ainsi un deploy reel bloque par
une image tenue par un conteneur arrete, et a revele quatre defauts corriges ici :
le programme de lecture des writers refusait tout identifiant, le superviseur du
builder SSH ecrivait ses recus en 0664 sous umask 0002, le nettoyage echouait sur
une image encore referencee au lieu de la conserver, et la migration du helper
refusait tout journal moderne a cause du champ `revision`, ce qui bloquait toute
mise a jour signee. La mise a jour suivante a revele deux autres impasses : la
migration refusait le dossier `baselines` que chaque deploy coordonne cree, et
une reservation `helper-update` echouee avant tout remplacement ne pouvait plus
etre reprise, bloquant toutes les operations globales. La migration accepte
maintenant ce dossier prive, et la reprise reconnait une mise a jour qui n'a
jamais remplace le helper. Un dernier defaut rendait pourtant toute mise a jour
impossible apres un deploy coordonne : le binaire candidat, lance par le helper
installe pour se sonder, relisait le journal sans lecteur d'inventaire writers.
Des qu'un inventaire ferme existait, il refusait dans son `init` et le helper
installe ne rapportait que « replacement binary does not expose the shuttle-root
interface ». La reproduction manuelle passait parce qu'elle ne lancait pas le
candidat depuis le dossier de staging, seul cas ou cette sonde s'active. Le
candidat et la reprise d'une migration lisent maintenant les inventaires comme
le helper parent. Un helper installe avant ces correctifs ne peut pas les
recevoir seul : sur le VPS de recette, des corrections root consignees ont
marque les reservations echouees `failed`, puis le helper corrige a ete installe
une fois hors flux signe. Il a ensuite repris par plan signe la derniere
reservation bloquee, et une mise a jour signee avec trois inventaires writers
presents a reussi.

## Builder SSH dedie avec cache persistant et arret du daemon

`build.runner: "ssh"` permet de compiler sur une VM ou un LXC de build distinct
sans deplacer le registre loopback du VPS. L'identite SSH est verifiee, le tunnel
part du builder et les images deployees restent identifiees par digest. Le mode
local reste le defaut quand la cle est absente.

La recette sur la VM PVE 232 a revele deux ecarts de transport reel et un daemon
qui survivait a la perte du client. Le wrapper accepte maintenant les arguments
OpenSSH emis par Docker, le superviseur conserve son entree de controle et il
arrete les conteneurs identifies de son run. Apres SIGKILL du client pendant un
build, le daemon s'arrete en 15 secondes ; le volume de cache est conserve.
Le controle SIGINT a aussi revele qu'un second appel a Close pouvait revenir
avant la fin du nettoyage lance par le gestionnaire de signal. Les appels
concurrents attendent maintenant le meme resultat de fermeture ; SIGINT et
SIGTERM ont ete verifies avec daemon arrete, tunnel ferme et cache conserve.
Les mauvaises cles, empreintes et cibles, ainsi qu'un port de tunnel occupe,
sont refuses sans bascule vers le poste local.

Changes since `v0.0.1`, newest first. Moved into the release notes when a tag
is cut.

## Current official releases were blocked by mandatory vulnerability scans

Setup and deployment required Trivy and refused the latest official images when
their embedded dependencies had HIGH findings. A missing scanner or scanner
outage also prevented delivery. The operator withdrew that mandatory gate on
2026-09-13: installation now checks current stable versions and exact digests,
without requesting vulnerability evidence or exceptions.

`doctor --scan-images` remains an optional diagnostic with dated reports and
honest failure results. Existing image pins, native PostgreSQL, rollback
retention and the refusal of implicit stateful major migrations are preserved.

## Every Swarm deploy was refused for an edge image it never installs

After the CVE gate shipped, an application with neither Redis nor RabbitMQ could
no longer deploy: `shuttle deploy` stopped on "image security verification
requires Trivy on PATH" before building anything. The deploy scanned the shared
Caddy image unconditionally, yet only `setup` and `setup --adopt` install or
replace the edge. With Trivy present the outcome would not have changed, since
the pinned official Caddy image still carried high findings on 2026-09-13, so
every release of every application was blocked on a component it left alone.

The gate now scans exactly the infrastructure images the running command
installs. Setup and adoption still scan the edge and the registry. A Swarm
deploy scans its Redis and RabbitMQ images when it enables them, and requires
no scanner when it selects nothing. Missing or failed evidence for a selected
image still refuses the operation, and `doctor --scan-images` still covers the
edge.

## Application data had no encrypted, independently verifiable recovery path

The local PostgreSQL backup timer protected against some operator mistakes, but
its files disappeared with the VPS. The existing offsite scripts belonged to
the commercial SQLite site and could not recover a Shuttle application.

`backup create` now quiesces the application's services, captures native
PostgreSQL databases, role definitions, declared volumes, deployed images and
recovery configuration, then restores service health before committing an
age-encrypted archive and an Ed25519-signed receipt. S3 and Cloudflare R2 export
are optional. Uploads are read back and hashed before their receipt is published;
fetching verifies an independent public key before downloading archive data.

`backup restore` verifies the entire archive before contacting its target. It
creates a separate native PostgreSQL cluster, nonlogin Unix owner, private Unix
socket, fresh volumes and recovery image tags. It compares table counts, image
IDs, file hashes and numeric permissions. The real VPS drill caught directory
ownership loss that kept Redis from entering its restored data directory, and
Debian PID-file handling for a cluster owned by a separate Unix account. Both
are corrected. No production database or volume is overwritten; public traffic
cutover remains an explicit operator operation after the isolated restore.

## New infrastructure selections must be stable, current and checked for CVEs

Project instructions now require native PostgreSQL under systemd, never Docker.
New configurations select stable PostgreSQL 18, with 16 and 17 still supported
for declared clusters and restores. The default changes no existing data files.
Redis 8.10.1-alpine, RabbitMQ 4.3.5-alpine and Caddy 2.11.4 are selected by pinned
digests, and stable-tag resolution detects a stale shipped infrastructure pin.

Setup, adoption and Swarm deployment now require Trivy evidence for selected
infrastructure images before their installation or promotion. The database must
be at most 24 hours old; missing evidence and high/critical findings refuse the
operation. `doctor --scan-images` runs that check without changing the VPS.
The official latest images examined on 2026-09-13 still have high CVEs, so these
new selections are not approved for installation. Existing VPS images were not
upgraded during this work. The helper also refuses an implicit Redis or RabbitMQ
major change against an existing data volume.

## A rebuilt Swarm image could report success while serving the previous code

On a fresh Debian 13 VPS, a first deployment served `v1-cold`. Changing the
test application's release file to `v2-warm` rebuilt a different image, but
the next deployment still served `v1-cold` despite a successful release
identity check. The application lived in a Git-ignored directory: Git still
reported a clean parent commit, so both builds received the same tag. The
push skipped any tag already present in the registry, and the identity check
then compared the running service to that old registry digest.

The push now publishes an available local image even when the registry tag
already exists. Docker deduplicates unchanged layers; tag existence alone
cannot establish content equality, including when a base image changes under
the same source commit. A registry-only retry still works when local cleanup
has removed the image, and the separate mode=max build cache remains intact.
Before replacing a tag, Shuttle preserves its previous manifest under a
digest-derived tag. Otherwise the registry's untagged-manifest cleanup could
delete a retained rollback image: the VPS cache masked that loss during the
first rollback test, but a direct registry request returned 404. Normal
retention removes the preserved manifest once neither retained stack uses
it. The regression test reproduces the skipped push, verifies preservation
before replacement, refuses a replacement when preservation fails, and
keeps registry-only retries working.

## A deploy that changed nothing restarted every service anyway

Under `deploy.strategy: compose`, a deploy of the Demo pre-production with no
code change and a warm build cache rebuilt three images to the exact IDs
already running, and `compose up` still stopped and recreated every service
using them: the API and its minute of start-up, the CRM poller, the backup
sidecar. Only `redis`, on a digest-pinned third-party image, could have been
left alone. Measured on 2026-09-12: 10 s to stop the old containers, 59 s for
the API to come back healthy, of a 1 min 37 promotion — for a release that was
byte for byte the one before it.

The cause is the immutable tag. Compose recreates a container when the hash of
its service configuration changes, and the image reference is part of that
hash. Every deploy renders `image: shuttle/demo-api:<version>` with a new
version, so every built service is a configuration change even when the
daemon reports the same image ID under both tags. Same ID, different string,
restart.

Now, once the images are built or loaded and their IDs read from the host, the
deploy reads what the project runs — per container, the image ID, the
reference it was created from, and the ID that reference resolves to today —
and a built service whose new tag is the image it already runs is rendered
with the reference it already runs. The service hash is then the one Compose
has, and the container is not touched; the retention keeps that reference
alive because the new release file names it, and the new tag of an unchanged
image is untagged by the same retention at the end of the run. A service whose
image did change gets its new tag and is recreated as before. Every ID in the
comparison is the host's own reading from the one daemon, so a reference
removed or re-pointed since the container started is never written into a
release, and only a reference in the repository this run built for is
eligible: a container started under the project by hand is not Shuttle's to
name. If the report cannot be read, the deploy says so and renders the new
tags as it always did — a recreation too many, never a reference the daemon
did not confirm.

What stays: the release identity check still compares the running containers
to the IDs this run loaded, and the tag per release is still what a changed
image carries. A release directory may now name a tag of an earlier release
for an unchanged service; `shuttle status` shows the reference the container
was actually created from, which is that one. Rollback is unchanged: the
previous release file names the references it ran, and they are retained.

## A host nobody may change had no way to be deployed to at all

Every `shuttle deploy` ended in the root helper, and the root helper was only
ever installed by `setup`. That is the product: a host Shuttle hardened,
deploying signed stacks as the least-privilege account it created. It left one
case with no answer. The Demo pre-production is a shared host, in service, on
which the team's only acceptable change is the name of the user allowed to
deploy — no `setup`, no `sudo` rule, not even a temporary one. The first
`setup` attempt on it, in September 2026, is what taught the team that.
Reaching that host meant `scripts/deploy.sh` and nothing Shuttle offered.

`deploy.strategy: compose` is that answer, and it is a strategy rather than an
option of the swarm one because it gives up what the swarm one is for. Shuttle
builds the images on the workstation with the same buildx pipeline, streams
them to the host with `docker save` over SSH into `docker load`, renders a
compose project, uploads it under the account's home and runs `docker compose
up -d --wait` as that account. The host key comes from `server.host_key` in
`config.json` — an out-of-band fingerprint, versioned with the configuration,
recorded on first contact and refused if it later changes — because no `setup`
is there to record one.

What it keeps is deliberate: the immutable tag per image and its identity
proven by image ID after the load and again on the running containers; the
per-service hardening, now factored into one function both renderers call so
the two cannot drift; the origin proof and availability probe; `current` and
`previous` on the host for rollback; the measured budgets that never gate. What
it gives up is written in the documentation in as many words: nothing
privileged enforces the hardening, `compose up` recreates services in place so
the probe reports the gap rather than rolling back, no Docker Secrets, no
shared edge. Every configuration key that would promise one of those — the
managed Redis and PostgreSQL, the edge routes and gates, secret owners, the
setup accounts — is refused under this strategy, naming the key and the reason.

Three things were found while writing it and fixed for this path. Compose
interpolation was left to the host: a `${VAR:-x}` in a compose environment
reached the daemon and was resolved against the deploy account's environment,
and a `${VAR:?}` guard resolved to an empty string. The rendered project is
now interpolated here, after `deploy.env_file` is loaded, a `:?` with an unset
variable stops the deploy naming it, and every literal dollar is escaped so a
password containing one arrives intact. A compose project name shared with a
stack somebody runs by hand would have let `--remove-orphans` delete that
stack; the project defaults to `shuttle-<app>` and the preflight refuses a name
whose project runs from files Shuttle did not write. And a two-minute SSH
deadline would have cut a five-hundred-megabyte image stream mid-transfer; the
stream's deadline is sized from the bytes to move.

The first real run found the fourth thing. The laptop is Apple silicon and the
host is x86; the images built on the laptop were arm64, would have loaded on
the host without a word and failed at exec on the first start — and building
them for amd64 under emulation is not an option either, since Bun crashes
under it. Every build now targets the host's architecture, and
`deploy.compose.build` decides where it runs: locally with a stream when the
architectures match, or on the host's own daemon through the docker CLI's SSH
transport when they do not, with Shuttle still driving the arguments, tags and
labels and the host only lending its CPU. That transport trusts OpenSSH's
known_hosts, so it is used only once that file is seen to hold the fingerprint
`server.host_key` pins.

The first successful run then found the fifth: the retention loop that removes
old release directories globbed `*/`, which matches a symlink to a directory,
and removed the `current` link it had just written while reporting success.
Links are excluded from that loop, and the loop is now executed for real in a
test, on a release root with three releases and two links.

Two smaller costs went with the measurements of that first run. The free-disk
and memory budgets each opened an SSH session of their own, on top of the
preflight's; over a VPN every session is a handshake, and a deploy made a
dozen in a row. Both figures now travel in the preflight report. And `--pull`
re-resolved every base image on every build; a Dockerfile whose bases are all
pinned by digest cannot receive anything from it, so it is skipped there and
kept everywhere an unpinned tag may have moved.

The owner's rule for this strategy is that nothing built for a deploy survives
it on the workstation. The image tags are removed when the command ends,
success or failure; `prune_build_cache: all` also removes the BuildKit builder
and the volume it keeps, which is the trade the documentation names: nothing
left behind, and a cold build next time.

Nothing changes for `deploy.strategy: swarm`: the loaded configuration is
marshalled byte for byte as before, and the Swarm stack is rendered by the
same code through the shared hardening function.

## `--adopt` refused every host Shuttle had not installed, and Swarm refused `live-restore`

Adoption exists to converge a host a previous Shuttle generation set up, and it
proves that by looking for `/opt/shuttle/<app>/state.json` before it does
anything. Nothing in this generation writes that file. So a host in service
that Shuttle never touched — a Compose stack somebody deploys by hand, with its
own accounts, its own firewall and its own `daemon.json` — could only be taken
through a fresh `setup`, which means first contact as `root`, a parked stack,
`dist-upgrade` and an unconditional reboot. On a Scaleway instance that path is
worse than fragile: the provider rewrites root's `authorized_keys` from its
metadata on every update of its agent, and the key that let the first stage in
is gone when the next one connects. That is how the first attempt on the Demo
pre-production ended on 2026-09-11, with the host rebuilt by hand.

`--adopt --unmanaged` takes such a host. The flag is explicit rather than the
gate being lifted, because "adopt" has meant "what Shuttle already installed"
since it existed, and the marker is how it tells a Shuttle host from an
unrelated machine. The survey now reports the marker's state instead of exiting
on it, and refuses only when the marker is absent, this generation has not
claimed the host either, and the flag was not given — so an interrupted claim
resumes without the flag, and the refusal text for the default case has not
moved a character.

The plan is written from what the survey found, never from the flag. It says
whether this run converges a Shuttle host, resumes a claim, or claims a host
that never was; and on that last kind it says what claiming changes, before
`--yes`, because three of those changes were discovered the hard way:

- `docker swarm init` refuses a daemon running with `live-restore`, and the
  Demo host runs with it. 20-docker now turns it off on an adopted host: the
  value is flipped in `daemon.json` with `jq` so every other key survives (log
  rotation lives there), the previous file is saved beside it, a file that is
  not JSON is refused rather than rewritten, dockerd is reloaded rather than
  restarted so no container stops, and `LiveRestoreEnabled` is asserted false
  before `swarm init` and again after. The plan states the consequence: from
  then on a dockerd restart or the deferred reboot restarts every container.
  `swarm init` also names its `--advertise-addr` on an adopted host, taken from
  the default-route interface, because an instance with a private-network NIC
  carries two global addresses and `swarm init` refuses to choose. The fresh
  stage is byte-identical, and now has the golden file the other stages had.
- 40-runtime resets the firewall to SSH and the declared public ports. A host
  in service publishes more — an API on 8001, a second front-end port, a
  database — and every one of them stopped answering with no warning. The
  survey lists what containers publish today, and the plan names the ports
  that will close and the key that keeps them.
- `--cutover-edge` stops the container on 80/443 and leaves its restart policy
  alone. Stopped is not gone: under `restart: always` the next dockerd restart
  — likelier now that live-restore is off — starts it again and races the edge
  for the ports. The cutover reads the policy, sets it to `no` after the stop,
  and puts the surveyed value back on the restore branch, so a failed cutover
  leaves the container exactly as it found it. The plan and the completion
  report both name the policy and the two commands that revert.

Two more lines in the plan cost nothing and would each have been an afternoon:
30-postgres installs a PostgreSQL server whether or not the application uses
one, and until the first `shuttle deploy` the edge serves no site on the ports
it just took. The deferred-work line about migrating the adopted database is
now printed only when there is an adopted database, which on a host Shuttle
never installed there is not. And the refusal for a first-contact account
without passwordless sudo — the first thing an operator meets on such a host —
now prints the sudoers line to write instead of naming the concept.

Nothing changes for an adoption without the flag, and nothing for a fresh
setup.

## `setup` locked out everyone on the host it was not told about

The signed SSH baseline names exactly who may log in, and it named `deploy`,
the declared operator, and under adoption the account the run arrived on. That
is the right list for a VPS one person owns. On a host other people log in to
— a shared pre-production, a server colleagues still deploy to through another
path — every other account lost SSH the moment the baseline committed, and
nothing in the plan said so: the dry run listed the accounts it would keep and
was silent about the ones it would not. The first `shuttle setup` on such a
host on 2026-09-10 ended with the host rebuilt by hand.

`setup.retained_users` and the repeatable `--retain-user` flag name the
accounts that must survive. A retained account is signed into `AllowUsers` and
nothing else happens to it: Shuttle creates none, installs no key, writes no
sudo rule and leaves group memberships alone. A `docker` or `sudo` membership
it holds is root-equivalent access today and stays so; that is the operator's
decision, and the plan and the final report say it in as many words instead
of hiding it. An account meant to be *changed* — given the managed sudo rule,
its groups reduced — is the operator, and an account cannot be both.

Retaining an account that could not log in afterwards would be the same
lockout with a plan claiming the opposite, so a read-only preflight refuses,
before anything is changed, an account that does not exist, is a system
account, has no login shell, or has no `authorized_keys` holding a key
`ssh-keygen` can read — the baseline closes password logins, so a key is the
only way in. Every refusal names the account and the reason.

What is proven afterwards is the directive, not the login: the post-hardening
audit already checks that `sshd` enforces the signed list, and no private key
of a retained account is held on the machine running `setup`, so unlike the
operator no session is opened as them. Under adoption they join the signed
list beside the administrators whose login is proven, and never enter those
proofs. `root` and `deploy` cannot be retained, neither can the operator, the
whole list fits the root helper's existing bound of 8 accounts, and retaining
the first-contact account while asking `--lock-out-first-contact-user` to
remove it is refused as the contradiction it is.

A configuration that names nobody produces the baseline, the plan and the
report it always produced, byte for byte.

## `make install` — running the build you just made

`scripts/release.sh` deliberately does not touch an installed binary, and
`shuttle update` is the user path: it downloads a signed release. Between
the two there was nothing, so running a freshly built CLI meant retyping a
`go build` with four `-ldflags` by hand. Getting one wrong is not loud: the
binary works, and only fails months later, on an update it can no longer verify.

`make install` builds for the current platform and replaces the binary on PATH,
retaining one generation as `shuttle.previous` so a bad install does not need a
rebuild to undo. It embeds the release verification keyring exactly as a release
build does, reading it from the GitHub Actions variables rather than keeping a
copy that could drift. Those keys are public; the signing key stays in CI. With
no authenticated `gh` the build still succeeds and says plainly that the result
will refuse `shuttle update`.

Developer tooling only. Nothing that ships to a customer changes.

## An environment overlay no longer blanks the base it layers onto

`shuttle deploy -e preprod` reads `config.preprod.json` over `config.json`. It
merged the two as decoded `Config` structs, and a Go struct cannot tell "absent"
from "zero": every field the overlay did not restate was marshalled as its zero
value and overwrote a perfectly good one. Sixty-one fields carry no `omitempty`,
so sixty-one values were destroyed by an overlay that never mentioned them.

The lucky case failed loudly. An overlay declaring a domain and a host — which
is the whole point of an overlay — reset `version` to 0 and the deploy stopped
on "unsupported configuration version 0: Shuttle requires version: 2", naming a
field the operator had written correctly. The unlucky cases had no such guard:
`app`, `deploy.retain`, `secrets.backend` and every `services.<name>.port` were
blanked in silence, and the operator would have read the consequences off a
deployed stack.

Merging the parsed documents instead of the decoded structs makes an overlay
mean what it looks like it means: only the keys it contains are replaced, at any
depth. `server: {host: ...}` now replaces the host and leaves `user` and `port`
where they were. Both files are still validated on their own first, so an
unknown field in an overlay is still an error and still names its own file, and
a named environment with no file beside the base is still not an error.

This is the mechanism's first working release. Anyone who had tried it and
concluded that `-e` was unusable was right.

## `secrets.backend: host` — credentials a workstation never holds

Every declared application secret had exactly one source: the encrypted local
store. That is the right default for an application deployed from the machine
that created it, and the wrong one for a server whose credentials already exist
and are meant to stay where they are. Adopting Shuttle for such a deployment
meant copying forty-odd live credentials onto a laptop so that Shuttle could
send them back to the machine they came from — a movement with no destination,
and one more place they can leak from.

`deploy.env_push` looked like the answer and was not. It is declared, it is
validated, and nothing reads it: no code path has ever uploaded or preserved an
environment file on the host. A `env_file` named in a compose file is read by
`os.ReadFile` on the workstation and materialised into the signed stack, so the
values were on the laptop and in `docker service inspect` either way.

`secrets.backend` now accepts `host` alongside `swarm`, with
`secrets.host.env_file` naming an absolute path **on the VPS**. The root helper
opens that file itself, takes only the keys the configuration declares, and
publishes them as Docker Secrets. Nothing travels: the CLI never sees a value,
the plan carries coordinates rather than material, and the stack receives object
names as it always has. What is mounted under `/run/secrets` is identical to
what the local store produces, so `expose: file` and `expose: env` behave the
same and no application code changes.

The mechanism is the one the managed Redis and PostgreSQL credentials have
always used — generated on the host, published by the helper, referenced by
name — generalised to secrets the operator owns rather than ones Shuttle
generates.

Versioning is what made this more than a file read. A Docker Secret is
immutable, so a changed value has to arrive under a new name, and the client
has to know that name before it can write the stack that mounts it. The local
store versions an entry with a random identifier it keeps beside the value; a
plain environment file has nowhere to keep one, and any identifier Shuttle
wrote next to it would fall out of step with the first edit nobody told Shuttle
about. The host backend hashes the value instead and returns a twelve-character
fragment, so editing the file *is* the rotation signal, and Swarm rolls the
service. A truncated digest is not a value: it changes when the value changes
and discloses nothing about what it is.

Reading a path the caller names is a power the helper did not have, so it is
bounded. `secrets-host` is the only action that accepts those coordinates, on
the same central guard that keeps secret material on exactly one action. The
path must be absolute and traversal-free, checked in the wire contract and
again by the helper. The file is opened with `O_NOFOLLOW`, must be regular, must
not be world-writable — a credential is worth what the weakest account able to
rewrite it is worth — and is bounded at 1 MiB. Only the declared keys are
extracted; a real `.env` holds far more than an application's secrets, and
taking it wholesale would publish as a credential every line anybody ever added
to it. A key that is present but blank counts as missing, because an empty
credential produces a container that starts, authenticates against nothing and
fails later.

The helper advertises `secrets-host`, and a configuration using the backend
requires it during the capability negotiation that already runs before the first
build. An older helper therefore refuses at the desk. The alternative would have
been a stack mounting objects nobody created, and services waiting for them
until the promotion budget ran out without ever saying why.

Missing keys are named. A deploy whose server does not set a declared secret
stops with the list of keys and the path to fix, rather than at convergence.

Two smaller corrections travel with it. An unknown `secrets.backend` now names
both accepted values instead of only the supported one — the half of the answer
the operator already had. And `shuttle secrets --file` no longer defaults to the
literal `.shuttle/secrets.enc`: it falls back to `secrets.file`, then to that
path. A project that had moved its store was read at the declared path by every
deploy and at the default path by every `shuttle secrets`, so `list` showed an
empty store for secrets that were there and `set` wrote a second one the deploy
never opened.

Nothing changes for `secrets.backend: swarm`, which remains the default when
`secrets.items` is declared and no backend is named.

## Two critical Next.js advisories closed, and the audit gate is green again

The daily Security Audit had been red since 09-09-2026. `bun audit` reported
five findings against the committed lockfile: two critical unauthenticated
remote code execution advisories in `next` below 15.5.24 (GHSA-p293-qw3h-jr36,
GHSA-2xp9-vwfh-vxw4), the libheif vulnerabilities reachable through `sharp`
below 0.35.4 (GHSA-rgj7-g3m4-5g8c), and the `js-yaml` merge-key denial of
service (GHSA-2883-xcg3-v3hh) under both `gray-matter` and `cosmiconfig`.

The floors move to `next` 15.5.25 and, in the overrides that already steer this
transitive, `sharp` 0.35.4. `js-yaml` needed neither: the declared ranges
already admit the fixed 3.15.2 and 4.3.2, and only the lockfile was stale.

Refreshing that lockfile is not surgical. Bun accepts nested overrides and
scoped resolutions without applying them, and removing a single entry by hand
makes it print `warn: Ignoring lockfile` and re-resolve everything. So the whole
tree moves to the latest version each declared range already allowed.

That carries `better-auth` from 1.6.26 to 1.7.3, which added a required
provisioning-origin argument to `internalAdapter.createUser`. `provisionBuyer`
declares `{ method: "admin" }`: a buyer row is created server-side from a paid
checkout, not from a sign-in flow, and the buyer authenticates later through the
email OTP plugin.

## Three readiness checks that failed on correct hosts

**`runtime.redis_service` never found a stack Redis.** `docker service ls
--filter name=` matches a service name by PREFIX, so `name=_redis` matched
nothing at all: Swarm names the service `<stack>_redis`. Measured on demo
(08-09-2026), `docker service ls` listed `demo_redis` and
`demo-preprod_redis` while the filtered form returned an empty set, and the
check reported "No application Redis Swarm service could be inspected" on a
host running two. The names are now listed and matched on the suffix.


**`ssh.allowed_users` broke as soon as an operator account existed.** `sshd -T`
prints one line per value of a repeatable directive, so the `AllowUsers deploy
ops` that setup itself signs comes back as two `allowusers` lines. The parser
kept the last one, so the check compared `[ops]` against `[deploy ops]` and
failed High — on every host using `--operator-user`, for a configuration
Shuttle had just written. Repeated directives are now joined.

**`filesystem.unmanaged_suid_sgid` reported a distribution binary.** Under
usrmerge `/bin` is a symlink to `/usr/bin`, and a package may register either
spelling: `fuse3` owns `/bin/fusermount3`, `find` walks `/usr/bin/fusermount3`,
and `dpkg-query -S` on that path finds nothing. Measured on Ubuntu 24.04:
`dpkg -V fuse3` clean, the check reporting one unmanaged privileged executable.
The check now tries the alternate spelling before reporting.

## A fresh setup no longer fails its own deploy-user readiness check

`setup` creates the deployment account with `useradd --create-home` and then
sets `.ssh` to 0700 and `authorized_keys` to 0600 — but never the home itself,
which keeps the distribution default (0750 on Ubuntu). `access.deploy_user_ssh_files`
requires 0700 on all three, so every freshly set up host reported a High
finding caused by the setup that had just run. Measured on a v0.0.6 host:
`homeMode: 750`. The home is now installed at 0700 in both the fresh and the
operator paths.

## `--skip-build` says what it needs instead of failing as `docker push`

The flag reuses an image the workstation already built — it is the retry path
for a deploy whose build succeeded and whose push or promotion did not. Used to
re-publish an unchanged stack, no build ran, the daemon held no such tag, and
the run died on:

```text
push 127.0.0.1:35979/demo-api:618304a: exit status 1
```

Nothing in that line names the flag, the image, or what to do. The push now
checks the local daemon first and refuses with the reason and the way out.

## The helper bootstrap no longer points at a door shuttle closed itself

A helper older than capability negotiation cannot replace itself, and the error
said to "bootstrap this release once with root access". But `shuttle setup`
writes `PermitRootLogin no`: the binary cannot be scp'd as root. Measured on a
v0.0.4 helper, the host stayed undeployable until someone found the provider
console by themselves.

The three messages now carry the route that works: copy the binary to the
deployment account, which is reachable, then install it from the provider
console as root. `signed-helper-update` (v0.0.6) makes this a one-time step for
hosts that have it; the ones that do not are exactly the ones reading this
error.

## `services.<name>.update_order` — one service may step aside before its replacement starts

Shuttle generated `order: start-first` for every service, unconditionally
(`swarm_stack.go`). That is what buys zero downtime on a single node, and it is
the right default. It is also fatal to one kind of service: a task holding an
**exclusive lock on a mounted volume**. Its replacement starts while it still
owns the file, cannot take the lock, and exits — Swarm then rolls the entire
stack back, and the release fails on a service nobody was changing.

Measured on `api` (demo, 04-09-2026), a Mercure hub on a BoltDB file:

```text
provision http.handlers.mercure.bolt: "": invalid transport: timeout
```

The outgoing task was still logging health checks 25 seconds after its
replacement had started. The stack file already carried the invariant in a
comment — « transport Bolt mono-writer. Jamais deux répliques, jamais
start-first » — and had no way to express it, since Shuttle generates the whole
`deploy:` block and replaces the file's.

`services.<name>.update_order` accepts `start-first` or `stop-first`. Unset means
`start-first`, so every existing configuration produces the same stack as before.
The same order is applied to `rollback_config`: reversing it during a rollback
would recreate the overlap at the worst possible moment.

**The published service may not opt out.** It is the one behind Caddy, and
stop-first there is not a slower rolling update — it is a window with nothing
answering. The configuration is refused at validation rather than discovered
mid-promotion.

This is an exception for lock-holding services, not a general knob.
