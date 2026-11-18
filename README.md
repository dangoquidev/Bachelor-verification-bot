# Bachelor Verification Bot

Bot Discord de vérification des étudiants de première année d'Epitech : chaque nouvel arrivant prouve qu'il possède une adresse `@epitech.eu` avant d'accéder au serveur.

## Fonctionnement

1. L'étudiant lance `/verify email:prenom.nom@epitech.eu` sur le serveur.
2. Le bot envoie un code à 6 caractères par email, via **Microsoft Graph** (compte Microsoft 365 de l'école).
3. L'étudiant colle le code dans le salon : le bot enregistre la vérification en base **MySQL**, lui attribue le rôle vérifié, le renomme `Prénom NOM` d'après son adresse, et supprime le message contenant le code.

```
Discord ──/verify──▶ Bot ──Graph API /me/sendMail──▶ Boîte mail étudiant
   ▲                  │
   └──── rôle + pseudo ◀── code saisi dans le salon
```

## Points techniques

- **OAuth2 délégué (MSAL)** : un petit serveur Express (`/login`, `/get_token`) permet à un administrateur de connecter le compte Microsoft qui envoie les emails ; les tokens sont rafraîchis silencieusement.
- **Persistance MySQL** : table `verified_users` avec contrainte `UNIQUE` sur l'email, qui garantit qu'une adresse ne vérifie qu'un seul compte même en cas de requêtes concurrentes ; requêtes préparées via un pool `mysql2`, schéma créé au démarrage, import automatique de l'ancien fichier CSV.
- **Anti-abus** : 3 demandes max par tranche de 15 minutes, 5 essais de code, expiration du code après 10 minutes, une adresse email ne peut vérifier qu'un seul compte Discord.
- **Codes générés avec `crypto.randomInt`** (générateur cryptographique).
- **Docker** : build multi-stage, exécution avec un utilisateur non-root, MySQL 8.4 dans Docker Compose avec healthcheck et volume persistant ; le bot attend que la base soit prête avant de démarrer.
- Logs horodatés et structurés pour suivre chaque vérification.

## Stack

TypeScript · Node.js · discord.js v14 · Express · MySQL 8.4 · MSAL Node · Microsoft Graph · Docker Compose

## Lancer le projet

Prérequis : une application Discord (bot) et une App Registration Azure AD avec la permission déléguée `Mail.Send`.

```bash
cp example.env .env   # renseigner les variables
docker compose up -d --build
```

Puis ouvrir `http://localhost:8000/login` une fois pour connecter le compte Microsoft expéditeur.

Sans Docker (nécessite un serveur MySQL accessible) :

```bash
npm install
npm run dev
```

| Variable | Rôle |
|---|---|
| `DISCORD_TOKEN` | Token du bot Discord |
| `VERIFIED_ROLE_NAME` | Nom du rôle attribué après vérification |
| `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` | App Registration Azure AD |
| `APP_BASE_URL`, `PORT`, `MSAL_REDIRECT_URI` | Serveur d'authentification |
| `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD` | Connexion MySQL |
| `MYSQL_ROOT_PASSWORD` | Mot de passe root du conteneur MySQL (Docker uniquement) |

## Structure

```
src/
├── index.ts                    # point d'entrée : serveur d'auth + bot
├── server.ts                   # routes Express OAuth2
├── auth/AuthService.ts         # MSAL : URL de login, échange du code, tokens
├── bot/EmailVerificationBot.ts # commande /verify, codes, rôles, rate limiting
├── db/VerificationStore.ts     # accès MySQL : schéma, lecture/écriture, import CSV
└── utils/index.html            # template de l'email
```
