# Harness core — noyau neutre de preuve et de discipline

Ce dépôt porte le noyau de preuve partagé entre plusieurs hôtes d'agent. Il ne
dépend d'aucun runtime d'agent : ni Pi, ni OpenCode.

## Pourquoi

Le harnais Pi avait construit deux choses qu'aucun hôte natif ne fournit :

- une base d'observations **immuables**, où réécrire une preuve lève une
  collision ;
- une liste de tâches qui **ne se ferme pas** sans une observation réussie.

Ces deux pièces étaient écrites en TypeScript mais vivaient dans le dépôt Pi,
ce qui rendait tout portage fragile. Elles vivent maintenant ici.

## Contenu

| Module | Rôle |
|---|---|
| `store.ts` | base d'observations, de connaissances et de règles opérateur ; empreintes de contenu, refus de réécriture |
| `tasks.ts` | liste de tâches ordonnée, `blocked` avec raison, clôture par preuve |
| `observation-id.ts` | identité d'une observation, dérivée de la session et de l'appel d'outil |
| `skill-trace.ts` | ce qu'un hôte a chargé pour un tour, et ce qu'il a écarté |
| `util.ts`, `types.ts` | socle commun |
| `process-evidence.ts` | lien observation ↔ appel d'outil |
| `sources.ts`, `platform-store.ts`, `platform-types.ts` | sources, findings citées, révisions |
| `memory-ranking.ts` | classement de la mémoire apprise |
| `process.ts` | commandes détachées, délai indépendant de l'hôte, registre et traces privées |
| `capsule.ts` | tâches et preuves, mission, approbations, commandes actives et références rappelées |

## Règle de neutralité

Un seul import d'un runtime d'hôte suffirait à réaccrocher ce dépôt à un hôte
et à casser le portage suivant. Le contrôle est mécanique et il est exécuté par
la suite de tests du harnais :

```bash
node scripts/check-neutrality.cjs
```

Il échoue si un module importe `@earendil-works/pi-`, `@opencode-ai/`, ou un
module local lié à un hôte, et si un import interne pointe un fichier absent.

## Consommateurs

- **Harnais Pi** : `~/.pi/agent/cyber-harness/` ré-exporte ce noyau. Les
  2 576 checks passent dessus.
- **OpenCode** : `opencode/` est l'adaptateur. Il est installé par **découverte**,
  `~/.config/opencode/plugins/harness-core` étant un lien vers ce dossier, qui
  expose `index.ts`. OpenCode rejette une entrée de config qui pointe un
  fichier, et ignore en silence un dossier sans `index.ts` racine. Le plugin
  n'importe rien : le cœur est atteint par chemin absolu (`HARNESS_CORE`), donc
  le même code sert en découverte, en copie ou en dossier package.

## Le store ne se duplique pas

Le store est un fichier, pas une bibliothèque. Les deux hôtes pointent sur la
même base, donc les preuves accumulées restent uniques et continues d'un hôte à
l'autre.

Les deux hôtes écrivent dans `~/.local/share/harness-core/state/`
(`HARNESS_STATE_ROOT`, ou `HARNESS_HOME` pour sa racine parente). La liste des tâches est relue à chaque usage, sans
cache : deux hôtes sur le même fichier ne peuvent pas diverger en silence.

## Les tests

`test/opencode-proof.cjs` conduit l'adaptateur sans modèle, et prouve les deux
garanties comme comportement : une tâche ne se ferme pas sans observation
réussie, et une observation ne peut pas être réécrite.

Le dépôt est autonome : `npm test` lance `test/run.cjs`, qui charge les suites
situées à côté du code qu'elles vérifient et compte les assertions réelles
(324 checks). La porte complète du harnais Pi reste disponible avec
`npm run test:gate` quand elle est installée.

## La porte en CI

`ci/verify.yml` est le workflow GitHub Actions de ce dépôt : `npm ci`, puis
`npm run check`, puis `npm test`, sur Node 24, à chaque push sur `main` et à
chaque pull request.

GitHub refuse d'écrire un fichier sous `.github/workflows/` avec un jeton qui
n'a pas le scope `workflow`, quel que soit le canal (push ou API). Le fichier
est donc versionné ici et s'active en une commande, avec un jeton porteur de
ce scope :

```bash
mkdir -p .github/workflows
cp ci/verify.yml .github/workflows/verify.yml
git add .github/workflows/verify.yml
git commit -m "ci: gate the core on every push"
git push
```

## Commandes tracées sur Linux

`cyber_process` expose `run`, `list`, `read` et `stop`. Le délai par défaut est
120 secondes, au plus 600. Le superviseur `/usr/bin/timeout` et son groupe
détaché survivent à la sortie du serveur ; après le délai, SIGTERM est suivi
de SIGKILL une seconde plus tard si nécessaire. Aucun paquet n'est installé.
`run` reçoit `argv` (exécutable puis arguments) et n'ouvre pas de shell
implicite. Une composition complexe doit vivre dans un script relu séparément.

Les traces complètes restent locales en mode `0600`. Leur lecture est bornée
et expurgée ; les commandes du registre sont aussi expurgées. Le registre
`processes.json` permet une reprise sans rejouer la commande. L'identité du
processus inclut le démarrage du système et du processus pour éviter de tuer
un PID réutilisé. `finished` signifie « plus actif », **pas** « sorti avec succès ».
Cela ne supervise pas un programme qui quitte volontairement son groupe.

Les permissions shell natives restent obligatoires. Sur OpenCode 2.0.26,
le client officiel appelle `session.permission.create` et le plugin attend
`permission.replied` si nécessaire. Il vérifie d'abord que le client atteint
le même PID serveur ; un serveur privé différent est refusé. Les versions
exposant `ctx.permission.assert` l'utilisent directement. Le rejet, la perte
du flux d'événements et l'annulation empêchent le lancement.

Les transitions réservées à l'opérateur utilisent l'action
`harness_operator`, configurée en `ask`. Elles exigent une réponse `once` : un
allow automatique ou mémorisé n'est jamais une décision humaine.

La mise à jour atomique du registre est verrouillée : une concurrence est
refusée plutôt qu'écrasée. Si l'hôte meurt pendant cette écriture, un verrou
résiduel peut demander une intervention ; il n'est jamais effacé à l'aveugle.
