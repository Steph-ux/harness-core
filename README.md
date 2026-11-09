# Harness core

Noyau de preuve et de suivi de mission pour OpenCode v2. Les observations,
constats, tâches et méthodes restent dans un état partagé indépendant de l’hôte.
L’adaptateur est dans `opencode/` ; `src/` utilise les modules natifs de Node.
Node 24 ou supérieur est requis. La supervision des commandes nécessite Linux
et un exécutable `node` accessible au serveur (`HARNESS_NODE` peut fixer son chemin).

## Installer dans OpenCode v2

La version native vérifiée est **2.0.26**, paquet npm `@opencode/cli`, commande
`opencode2`. Le paquet `opencode-ai` appartient à l’autre ligne de versions.

Définir `HARNESS_CORE` avec le chemin absolu de ce dépôt. Ajouter le **dossier**
`opencode/` au tableau `plugins` de la configuration existante, en conservant
les autres réglages et plugins :

```json
{
  "plugins": ["/chemin/absolu/harness-core/opencode"],
  "permissions": [
    {"action": "harness_operator", "resource": "*", "effect": "ask"}
  ]
}
```

Le dossier expose `index.ts`. La découverte via
`~/.config/opencode/plugins/harness-core` est une autre possibilité ; choisir
une seule méthode pour éviter un identifiant de plugin en double. Attendre
l’activation du lieu avant de lire son catalogue. Vérifier ensuite
`harness-core.proof` dans `plugin.list` et les deux procédures dans `skill.list`.

`capitaliser-cyber` et `rapports-cyber` sont servies depuis `.opencode/skills/`.
Les autres méthodes `harness-*` du routeur appartiennent à un catalogue externe.
Leur absence doit être résolue avant une opération qui les exige. Un chargement
en erreur ne satisfait jamais cette exigence.

## Garanties et limites

- Les observations opérationnelles sont immuables et limitées à leur périmètre.
  L’empreinte couvre toute la sortie, même au-delà de l’extrait conservé. Les
  entrées et sorties destinées au modèle sont expurgées.
- Un lancement de commande ne prouve pas sa réussite. `cyber_process read`
  vérifie toute la trace et ne donne une preuve réussie qu’après une fin avec
  code 0. États : `running`, `succeeded`, `failed`, `timed_out`, `stopped`,
  `unknown`. Un processus ancien sans résultat fiable reste `unknown`.
- Le superviseur Node est indépendant du serveur. Délai par défaut : 120 s ;
  maximum : 600 s. Les descendants dans le groupe qui survivent à leur parent
  sont arrêtés et font échouer le résultat. Un programme qui quitte
  volontairement son groupe n’est pas entièrement supervisable ici.
- Les commandes du registre et les lectures sont expurgées. Les traces,
  résultats et fichiers de contrôle complets restent locaux, sous accès
  restreint. La clé de contrôle d’une exécution n’est pas renvoyée au modèle.
- Un verrou couvre toute mutation des tâches. Un conflit demande une nouvelle
  tentative. Les tâches ne sont pas tronquées aux vingt dernières. Une
  dépendance absente ou bloquée empêche le départ ; une clôture sans preuve
  valide reste visible comme blocage lors de la reprise.
- La vérification d’un constat lie sa révision à une reproduction et un
  contrôle négatif observés dans une session distincte, après sa création et
  après toute reprise de validation. Elle ne vaut pas approbation humaine.
  Un marqueur prouve le résultat observé ; l’analyse doit justifier l’impact.
- Le harnais suit les preuves et les permissions. Il ne constitue pas un
  confinement réseau et ne déduit pas une autorisation de cible d’un dossier.
  Définir le mandat et le périmètre dans la mission.

Les permissions shell natives restent obligatoires. Sur 2.0.26, le repli par
le client CLI officiel vérifie qu’il atteint le même PID serveur. Un serveur
privé différent est refusé. Les versions qui exposent
`ctx.permission.assert` l’utilisent directement. Les transitions opérateur
exigent une réponse `once` à `harness_operator` en `ask` ; un `allow` mémorisé
ne vaut pas décision humaine.

## Rapports et restitution

La procédure `rapports-cyber` décrit ce parcours :

1. Enregistrer observations, sources et constats. Produire les attestations
   avec `cyber_verification`, puis terminer l’étape `validation` en les citant
   et vérifier les constats avec `cyber_finding verify`.
2. Créer `cyber_report snapshot` avec les détails éditoriaux. Les vulnérabilités
   doivent être vérifiées ; les observations et cas non testés gardent leur
   classement. Les sources et empreintes sont figées.
3. Générer Word, PDF et images de toutes les pages avec le script fourni.
   Enregistrer les trois artefacts et les relier avec `cyber_report register`.
4. Relire toutes les pages et enregistrer la décision du responsable. L’étape
   `report` exige le dernier rapport approuvé et ses fichiers inchangés. Une
   modification des constats invalide la revue et rouvre le rapport.
5. Si la validation doit être reprise, utiliser `cyber_mission reopen-validation`
   avec une raison. Après décision de l’opérateur, le harnais conserve les
   checkpoints, remet les constats à vérifier et rouvre validation, preuves et
   rapport. Les anciennes observations de vérification ne peuvent pas être
   réutilisées comme preuves fraîches de cette reprise. Aucun test externe
   n’est relancé automatiquement.
6. Consigner la restitution effective avec l’accord de l’opérateur et sa
   preuve. Une restitution prévue ne vaut pas restitution effectuée.
7. **Nettoyer uniquement après restitution** avec `cyber_cleanup` :
   `plan` → `run` → `result` → `verify` → `result`.
   L’exécution et sa vérification utilisent des processus distincts. Conserver
   jusque-là les preuves, comptes et objets de test selon le mandat. Aucun PoC,
   générateur ou passage de capitalisation ne les supprime automatiquement.

Les transitions et leurs événements sont écrits dans une transaction. Les
transitions concurrentes de nettoyage sont refusées avant le lancement. Une
clôture de rapport et le suivi après restitution sont distincts :
`cyber_report status` expose restitution, capitalisation et nettoyage. Ne pas
annoncer le dossier entièrement clos si ces actions restent à traiter.

Le générateur local ne lance pas les PoC du snapshot :

```bash
python3 -m pip install -r .opencode/skills/rapports-cyber/scripts/requirements.txt
# Installer aussi LibreOffice, Poppler et DejaVu Sans Mono ou une police équivalente.
python3 .opencode/skills/rapports-cyber/scripts/build_report.py /mission/snapshot.json --out /mission/rapport-v2
```

Il refuse d’écraser une version existante et produit `rapport.docx`,
`rapport.pdf`, `page-N.png`, `qa.json`. `SOFFICE` peut désigner LibreOffice.
Le manifeste relie les empreintes et laisse la revue visuelle en attente.
Le calcul couvre le **score de base CVSS 3.1 uniquement**, selon
[FIRST](https://www.first.org/cvss/v3.1/specification-document). Un vecteur non
pris en charge ou un score incohérent est refusé. Justifier séparément les
métriques et le risque métier.

`cyber_capture shot` photographie une fenêtre réelle. `evidence` affiche une
trace enregistrée liée au processus lu, sans le rejouer. Cette seconde forme
porte `rendered-trace` et ne doit pas être présentée comme capture native du test.

## Capitaliser Cyber

Une passe bornée transforme les apprentissages vérifiés en scripts, règles,
fixtures ou procédures. `cyber_capitalise` consigne `none`, `candidate` ou
`validated`. La validation exige un artefact ainsi que des tests positifs et
négatifs distincts. L’absence d’apprentissage utile est un résultat valable. Cette
passe ne modifie pas les poids du modèle et ne génère pas récursivement des skills.

Les méthodes apprises exigent toujours deux sessions de support et une confiance
≥ 0,75 pour devenir actives. La promotion globale exige une décision de l’opérateur
et des exemples anonymisés. La capitalisation ne vaut pas autorisation de nettoyage.

L’extraction automatique attend dix minutes d’inactivité. Elle compare les
empreintes des observations : une session reprise peut être relue et un échec
retenté après une minute. `HARNESS_VERIFIER` ou `state/verifier` fixe un modèle
exclusif. Sans modèle fixé, le fournisseur de la session demandeuse est réutilisé ; les autres
ne sont envisagés que dans `HARNESS_VERIFIER_PROVIDERS`. Maximum trois candidats,
30 s par appel et 24 000 caractères de réponse acceptée. **L’API stateless de
2.0.26 n’expose pas de plafond de tokens en sortie** ; la limite de caractères
n’est pas un plafond de facturation serveur.

## État et migration

`HARNESS_HOME` vaut par défaut `~/.local/share/harness-core`.
`HARNESS_STATE_ROOT` peut fixer directement le dossier d’état.

| Fichier | Contenu |
|---|---|
| `knowledge.sqlite` | Sessions, observations, connaissances, règles et audits |
| `platform.sqlite` | Missions, constats, sources, artefacts, rapports, restitutions et nettoyage |
| `tasks-<scope>.json` | Tâches verrouillées par périmètre |
| `processes.json`, `traces/` | Exécutions, traces privées, résultats et fichiers de contrôle |
| `reports/` | Snapshots de rapport conservés par version |
| `skills/` | Révisions et méthodes apprises |

Les migrations SQLite sont additives. Aucun hash complet manquant n’est inventé
pour les anciennes observations, et aucun ancien processus n’est transformé en
réussite. Sauvegarder l’état avant une mise à niveau ; ne pas ouvrir une base
migrée avec une version antérieure. Un verrou abandonné nécessite une inspection,
pas une suppression automatique.

## Vérifier

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run check             # TypeScript, neutralité et ressources des procédures
npm test                  # suites autonomes, sans modèle externe
python3 test/report-pipeline.py
npm run test:report       # dépendances de rendu nécessaires
OPENCODE_BINARY=/chemin/opencode2 node scripts/native-smoke.cjs
```

Les tests utilisent des fixtures synthétiques sans cible client. Le contrôle
natif 2.0.26 couvre le catalogue, les outils dans leur périmètre et le refus du
serveur privé. Les événements d’exécution, décisions `once` et résultats de
commandes sont vérifiés avec un hôte de test. Aucun parcours natif avec modèle
externe n’est revendiqué. Les captures sur fenêtres réelles exigent un écran.
Le contrôle Pi externe reste optionnel avec `npm run test:gate` ou `HARNESS_PI_GATE`.

Le workflow `.github/workflows/verify.yml` exécute trois contrôles sur les PR :
contrats du noyau, génération réelle Word/PDF et chargement natif OpenCode 2.0.26.
Les pages rendues sont conservées comme artefact CI pour la revue visuelle humaine.
`ci/verify.yml` en conserve une copie ; seul le chemin `.github/workflows/` est actif.

Les décisions sont dans `DECISIONS.md`, la carte des modules dans `src/ARCHITECTURE.md`.

## Outils vivants : découverte, création et réutilisation pendant la session

Le plugin OpenCode expose `cyber_toolbox`. Son registre partagé est conservé sous
`HARNESS_STATE_ROOT/capabilities/registry.json`, hors du dépôt. Une mission
peut proposer, tester, valider et activer un script **sans changer de session**.
Les sessions ouvertes relisent l'index au prochain contexte ou appel à
`cyber_toolbox discover`. Les scripts activés sont accessibles **immédiatement**
à travers les outils de shell/processus existants et leurs permissions. Le
plugin n'ajoute pas dynamiquement un outil natif OpenCode par script.

- `discover` : classe les commandes du `PATH`, du répertoire
  `HARNESS_TOOL_HOME` (par défaut `~/hacking/Mes-outils`), des chemins
  `HARNESS_TOOL_PATHS`, les scripts gérés et les outils du catalogue hôte.
  Ce n'est pas une preuve d'exécution. Les chemins liés sont ignorés.
- `plan` : compare jusqu'à 25 objectifs à l'inventaire courant. Un match
  indique seulement un outil candidat, jamais une couverture réellement testée.
- `list` : renvoie les versions du périmètre, avec les candidats et l'historique.
- `propose` : écrit une version **candidate**, sans l'exécuter ni la rendre
  disponible pour d'autres missions. Formats pris en charge : `mjs`, `py`,
  `sh`. Les candidats restent isolés sous `capabilities/staging/`.
- `validate` : contrôle la syntaxe sans lancer le script, puis exige deux
  observations réussies distinctes (test positif et test négatif) issues du
  même périmètre, contenant le chemin exact du candidat et le résultat
  attendu. Les deux exécutions doivent préalablement avoir été effectuées
  avec les outils autorisés de l'hôte ; la simple sortie d'un générateur de
  texte ne constitue pas une preuve.
- `activate` : rend immédiatement la version validée visible pour son projet,
  en retirant la précédente de l'index actif. Les fichiers publiés sont
  contrôlés par SHA-256 avant chaque utilisation.
- `promote` : requiert une décision explicite de l'opérateur, copie le script
  validé dans le registre global et vérifie l'absence d'identifiants de cible
  courants. Les preuves restent dans le projet source.
- `rollback` : requiert une décision explicite de l'opérateur, et ne peut
  restaurer qu'une version ayant déjà été validée.

Le contexte présente une sélection courte du catalogue, recalculée à chaque
tour. L'événement d'audit `tools.executed` distingue les appels réellement
observés de `tools.discovered`. Cela ne garantit pas que le modèle choisira
toujours la meilleure commande : la couverture doit être vérifiée sur les
observations et les objectifs d'une mission.

La création de fichiers n'accorde ni autorisation de cible ni accès système
supplémentaire. La validation ne remplace pas une revue de sécurité humaine.
Les preuves d'exécution et les tests en conditions réelles sous Kali restent
à effectuer sur l'environnement de l'opérateur. Aucun outil candidat n'est
exécuté automatiquement par le registre.

