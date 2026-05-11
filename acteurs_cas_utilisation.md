# Acteurs et Cas d'Utilisation - Système Crypton (FastAPI)

Ce document répertorie les différents acteurs interagissant avec l'API FastAPI et leurs cas d'utilisation associés, basés sur l'implémentation actuelle.

---

## 1. Utilisateur (User)
L'acteur principal qui utilise les services de sécurité pour son usage personnel.

### Authentification & Profil
- **S'inscrire** : Créer un compte avec vérification par e-mail.
- **Se connecter / Se déconnecter** : Accéder à son espace via JWT (Access & Refresh tokens).
- **Gérer son profil** : Mettre à jour son nom, téléphone et mot de passe.
- **Réinitialiser le mot de passe** : Récupérer l'accès via un code envoyé par e-mail.

### Antivirus & Analyse
- **Lancer un scan manuel** : Analyser un fichier ou un répertoire spécifique sur le système.
- **Consulter l'historique** : Voir les rapports de scans précédents.
- **Nettoyer l'historique** : Supprimer d'anciens rapports de scan.

### Gestion de la Quarantaine
- **Lister la quarantaine** : Voir les fichiers dangereux mis à l'écart (filtré par propriété).
- **Restaurer un fichier** : Replacer un fichier de la quarantaine vers son emplacement d'origine.
- **Supprimer définitivement** : Effacer totalement un fichier infecté de la quarantaine.

### Coffre-fort (Vault)
- **Sécuriser (Chiffrer) un fichier** : Uploader un fichier pour le stocker de manière chiffrée.
- **Lister le coffre** : Voir ses fichiers sécurisés.
- **Déchiffrer / Télécharger** : Récupérer un fichier du coffre dans son état d'origine.
- **Supprimer du coffre** : Retirer définitivement un fichier sécurisé.

### Paramètres & Monitoring
- **Gérer les paramètres** : Configurer les options de scan, l'analyse IA, et les politiques de nettoyage.
- **Suivre les événements** : Visualiser les activités détectées en temps réel sur le système.

---

## 2. Administrateur (Superadmin)
Utilisateur disposant de privilèges élevés pour la gestion globale du système.

- **Créer des utilisateurs** : Ajouter manuellement de nouveaux comptes au système.
- **Bannir / Débannir** : Suspendre l'accès d'un utilisateur pour des raisons de sécurité ou de politique.
- **Superviser les données** : Accéder à une vue d'ensemble des données et statistiques du système.
- **Communiquer** : Envoyer des e-mails administratifs ou des notifications aux utilisateurs.

---

## 3. Système / Moniteur Temps Réel (System / Monitor)
Acteur logiciel automatisé agissant en arrière-plan.

- **Surveiller le système de fichiers** : Détecter les modifications, créations ou suppressions de fichiers en continu.
- **Déclencher des analyses automatiques** : Lancer le scanner lorsqu'une menace potentielle ou un nouveau fichier est détecté.
- **Gérer les logs** : Enregistrer les événements système pour audit.

---

## 4. Scanner SSH / Agent Distant (Software Actor)
Composant technique permettant l'extension des capacités de scan.

- **Se connecter à distance** : Établir une session sécurisée avec un serveur distant via SSH.
- **Exécuter des scans distants** : Déployer et lancer le moteur d'analyse sur des infrastructures tierces.
- **Rapatrier les résultats** : Transférer les rapports de vulnérabilités vers l'API centrale.
---

## 5. Scénarios d'Utilisation

Voici quelques exemples concrets illustrant le fonctionnement du système pour les principaux cas d'utilisation.

### Scénario A : Détection et Scan Manuel (Utilisateur)
1. **Action** : Un utilisateur télécharge un fichier compressé suspect et souhaite vérifier sa dangerosité.
2. **Déroulement** :
   - L'utilisateur se rend dans la section "Antivirus" et sélectionne le fichier pour un scan manuel.
   - L'API FastAPI transmet la commande au binaire `av-shield`.
   - Le système identifie une menace connue dans l'archive.
3. **Résultat** : Un rapport de scan est généré, notifiant l'utilisateur de la présence d'un malware. L'utilisateur choisit ensuite de placer le fichier en quarantaine via l'interface.

### Scénario B : Gestion de la Sécurité (Administrateur)
1. **Action** : L'administrateur remarque via les logs qu'un compte utilisateur envoie un volume anormal de requêtes suspectes.
2. **Déroulement** :
   - L'administrateur utilise le endpoint `/admin/users/ban` pour suspendre le compte de l'utilisateur.
   - Le système met à jour la table `banned_users` dans la base de données.
   - Lorsque l'utilisateur tente une nouvelle connexion, le système intercepte la requête et renvoie le message : "Votre compte a été banni".
3. **Résultat** : L'accès au système est immédiatement bloqué pour cet utilisateur jusqu'à ce que l'administrateur décide de le débannir (via `/admin/users/unban`).

### Scénario C : Analyse Automatique en Temps Réel (Système)
1. **Action** : Une application tierce dépose silencieusement un script malveillant dans un dossier surveillé.
2. **Déroulement** :
   - Le `realtime_monitor` détecte instantanément l'événement `IN_CREATE` via les services du kernel.
   - Le système déclenche une analyse automatique en arrière-plan sans intervention humaine.
   - Le scanner confirme que le script contient une signature suspecte.
3. **Résultat** : Le script est immédiatement déplacé en quarantaine, et l'événement est enregistré dans l'API des événements en temps réel pour consultation par l'utilisateur.
