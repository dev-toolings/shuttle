# ADR 0001 : tout Shuttle est Apache-2.0

Date : 2026-11-05
Statut : accepted

## Contexte

Le site de distribution a été retiré le 2026-09-14. Depuis, aucune fonction
n'a jamais été conditionnée à quoi que ce soit, et le code qui préparait une
vente n'était branché sur rien. La priorité est de livrer un produit stable et
fonctionnel.

## Décision

Le CLI, le helper, les templates, le backup local et distant, les alertes et
la doc d'exploitation sont Apache-2.0. Apache-2.0 plutôt que MIT : grant de
brevets explicite.

Un seul binaire, sans édition ni condition d'usage. `shuttle update` ne
présente aucun identifiant : c'est la signature de la release qui fait foi.

## Hors périmètre

Origine GitHub de `shuttle update`.

## Invariants conservés

PostgreSQL reste natif sous systemd. Pas de Postgres Docker en production.
Compte `deploy` hors sudo et hors docker. Helper root signé, pas de shell dans
les plans. Images digest-pinned.
