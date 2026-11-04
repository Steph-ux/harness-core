# Contrat et validation d’un artefact cyber

## Fiche minimale à adapter

- **Objectif :** une opération et son bénéfice attendu.
- **Preuve d’origine :** observation reproduite, correction vérifiée ou besoin répétitif ; ne pas inclure de secret.
- **Périmètre :** formats, versions et environnements couverts.
- **Entrées :** paramètres, types, encodage, taille maximale utile, contraintes.
- **Sorties :** schéma, unités, ordre si significatif, codes d’erreur.
- **Effets :** fichiers modifiés, accès réseau, privilèges ; indiquer « aucun » quand vérifié.
- **Usage :** commande ou procédure minimale avec valeurs fictives.
- **Validation :** cas exécutés, résultats et limites non testées.
- **Maintenance :** dépendances, hypothèses à revérifier et retour arrière si nécessaire.

Intégrer ces informations dans les docstrings, l’aide CLI ou la référence pertinente, sans multiplier les documents. Utiliser un schéma structuré uniquement si un consommateur en a besoin.

## Exemples de promotion

### Analyse de journaux

Après plusieurs corrections vérifiées d’un parseur d’horodatages, compléter le parseur existant. Tester fuseau explicite, entrée malformée et changement de date. Paramétrer les champs ; ne pas embarquer les journaux du client. Indiquer le nombre d’entrées ignorées au lieu de les masquer.

### Détection

Après une investigation, produire une règle seulement si les champs nécessaires sont disponibles. Fournir événements synthétiques positifs et négatifs, expliquer les faux positifs plausibles et le périmètre. Ne pas présenter une correspondance comme preuve de compromission. Ne pas déployer la règle en production sans autorisation correspondante.

### Durcissement

Transformer une vérification récurrente en contrôleur de configuration en lecture seule. Distinguer « conforme », « non conforme » et « indéterminé ». Une donnée absente n’est pas une conformité. Séparer toute correction active de l’évaluation ; prévoir sauvegarde et restauration pour les changements autorisés.

### Résultat incertain

Un scanner émet une alerte sans reproduction ni preuve indépendante. Conserver l’incertitude dans le rapport et proposer une vérification adaptée. Ne pas générer automatiquement un outil d’exploitation ni une règle universelle à partir de cette seule alerte.

## Vérification de mise à jour

Comparer l’ancien et le nouveau comportement sur les mêmes fixtures. Préserver les interfaces utilisées. Si un format change, prévoir une migration explicite. Ne pas confondre réussite des tests synthétiques et validation opérationnelle complète. Arrêter la capitalisation après la livraison de l’amélioration utile, sans générer des outils pour tester indéfiniment d’autres outils.
