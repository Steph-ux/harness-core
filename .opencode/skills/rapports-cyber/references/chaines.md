# Chaînes d'exploitation

Une vulnérabilité isolée se classe au niveau qu'elle prouve. Une chaîne se classe au niveau de son dernier maillon. Avant de classer, chercher si A permet B.

| Constat A | Vérifier B | Impact combiné |
|---|---|---|
| IDOR en lecture | le même identifiant en écriture ou suppression | plusieurs constats élevés |
| Contournement d’authentification | les endpoints voisins du même contrôleur | idem |
| XSS stocké | un rôle administrateur voit la page | élévation de privilèges |
| SSRF | 169.254.169.254, service interne, ou callback sortant | critique |
| Redirection ouverte | `redirect_uri` OAuth | vol de code, prise de compte |
| Bucket S3 listable | bundles JS, puis secrets, puis OAuth | moyen à élevé |
| Introspection GraphQL | mutation sans contrôle d’accès | élevé |
| Injection de prompt | accès aux données d’un autre utilisateur | élevé |
| Traversée de chemin | `/proc/self/environ` ou lecture de clés | exécution |
| Sous-domaine détournable | `redirect_uri` OAuth sur ce sous-domaine | critique |
| JWT à secret faible | forger un jeton administrateur | critique |
| Upload contourné | SVG vers XSS, ou exécution côté serveur | élevé à critique |

## Règles

- Chaque maillon est observé : reproduction **et** contrôle négatif. Un maillon non observé n’existe pas.
- Une chaîne non prouvée reste une hypothèse, classée `not-reproduced` ; ne pas additionner des impacts non observés.
- La chaîne se consigne dans le graphe d’entités (`cyber_entity relate`, kind `chains-with`) et se cite dans le rapport comme chemin d’attaque, maillon par maillon.
- Ne jamais présenter une chaîne théorique comme un chemin validé : le rapport sépare ce qui a été exécuté de ce qui reste à vérifier.

Source : table adaptée de `awarexone/Agentic-Bug-Hunter` (`bughunter/agents/chain-builder.md`, licence MIT).
