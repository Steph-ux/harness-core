# Méthode des rapports

## Contenu client

- Synthèse décisionnelle : résultat démontré, actifs concernés, actions prioritaires et limites.
- Périmètre, période, auteur et méthode effectivement appliquée.
- Tableau séparant vulnérabilités, observations et cas non testés ou non reproduits.
- Fiche par constat : actif, prérequis, description factuelle, étapes reproductibles, résultat observé, contrôle négatif, impact prouvé, limites, correction et critère de clôture.
- Preuves lisibles : horodatage, commande ou requête réellement observée, sortie pertinente et capture originale disponible.
- Plan de remédiation sans inventer de responsable ni d’échéance. Séparer sévérité technique et risque métier.
- Restitution puis nettoyage selon le mandat, sans suppression automatique avant restitution.

## Rédaction et confidentialité

Rédiger en français professionnel, avec des phrases courtes et précises. Pas de tirets cadratins. Ne pas ajouter de DSI ou de destinataire technique par défaut. Ne pas exposer au client les notions internes de déduplication, identifiant canonique ou ancien identifiant. Ne pas extrapoler une chaîne d’attaque non exécutée.

Expurger mots de passe, cookies, clés, jetons et données personnelles des extraits client. Conserver les originaux sous accès restreint selon le mandat. Une trace affichée après coup porte la légende « trace enregistrée » ; ne pas la présenter comme une capture native du test.

## Livrables, preuves et annexes

Le dossier de l'engagement sépare quatre natures, et le harnais refuse un objet rangé ailleurs :

| Contenu | Dossier | Artefact |
|---|---|---|
| Script reproductible d'un constat | `pocs/` | `poc` |
| Outil ou script réutilisable livré avec la mission | `pocs/` | `script` |
| Capture d'écran d'une commande exécutée | `preuves/captures/` | `capture` (PNG ou JPEG) |
| Corps de réponse, en-têtes, page HTML, archive réellement extraite | `preuves/dumps/` | `dump` |
| Entrée de test, échantillon synthétique | `preuves/fixtures/` | `fixture` |
| Extrait expurgé destiné au rapport | `preuves/extraits/` | `evidence` |
| Règle de détection | `regles/` | `rule` |
| Word, PDF, QA | `rapport-vN/` | `report-*` |

Un corps de réponse n'est pas une preuve. La preuve d'une requête est l'observation produite par la commande réellement exécutée, puis l'attestation visuelle de sa trace enregistrée. Un fichier texte qui contient une réponse HTTP n'est qu'une annexe : il ne remplace ni la commande tracée, ni la capture. Un fichier de test ne se range jamais avec les dumps.

Le dossier d'une version de rapport est créé par `cyber_report action=snapshot` et renvoyé dans `reportDir` ; le générateur refuse d'écraser une version existante.

## Captures navigateur

Aucune capture ne doit montrer la mention « Chrome est contrôlé par un logiciel de test automatisé », ni son équivalent dans un autre navigateur. Une image qui porte ce bandeau est refusée : elle prouve l'outillage, pas la page.

- Chromium, Chrome et Edge : lancer avec `--test-type`, qui supprime précisément ce bandeau. Jamais `--no-sandbox`.
- Playwright ou Puppeteer : `ignoreDefaultArgs: ["--enable-automation"]` (le pilote ajoute ce drapeau par défaut), ou `--test-type` dans les `args`.
- Firefox et Safari n'affichent pas ce bandeau ; vérifier quand même l'image.
- Ne jamais rogner l'image pour faire disparaître le bandeau : la barre d'adresse reste visible, elle porte l'URL de la preuve.
- Relire l'image après la capture. Si le bandeau est présent, relancer avec le bon drapeau et reprendre la capture.

## Couverture

Le rapport porte une table de couverture : OWASP Top 10 (2021) et techniques MITRE ATT&CK. Chaque ligne vaut `tested`, `not-tested` ou `not-applicable` ; une ligne non testée ou non applicable porte sa raison. La couverture ne se déduit pas du nombre de constats : elle se déclare élément par élément, et le snapshot la transporte dans `coverage`.

Un constat cite la catégorie OWASP et la technique MITRE qu'il illustre. Une catégorie absente de la table n'a pas été examinée ; une catégorie présente sans raison n'est pas acceptable.

## Contrat du générateur

Entrée : snapshot JSON issu de `cyber_report snapshot`, schéma 1. Sorties : `rapport.docx`, `rapport.pdf`, `page-N.png`, `qa.json`, écrites dans le `reportDir` renvoyé par le snapshot, sous `<engagement>/rapport-vN`. Le DOCX porte la couverture (client, référence, périmètre, période, édition, classification en pied de première page), un sommaire paginé calculé sur le rendu réel, un en-tête courant et un pied de page avec `page / total`. Les trois artefacts enregistrés (DOCX, PDF, QA) doivent rester sous ce dossier ; `cyber_report action=artifact` refuse un chemin hors de `<engagement>/rapport-vN`. Le manifeste porte les empreintes du snapshot, des livrables et des images, sans déclarer la revue visuelle effectuée. Le script n’exécute aucun PoC ni commande fournie dans le snapshot et ne télécharge pas d’image.

Le score de base CVSS 3.1 suit FIRST : https://www.first.org/cvss/v3.1/specification-document . Refuser un vecteur incomplet, une métrique répétée, un format non pris en charge ou un score incohérent. Justifier les métriques à partir des preuves ; la formule seule ne prouve pas leur pertinence.

Pour reprendre une validation clôturée, `cyber_mission reopen-validation` exige une raison et une décision explicite de l’opérateur. La reprise conserve les checkpoints, remet les constats à vérifier et rouvre validation, preuves et rapport. Les effets externes ne sont jamais rejoués automatiquement.
