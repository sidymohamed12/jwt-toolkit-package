# Guide développeur — JWT Toolkit

Ce document s'adresse à qui développe, maintient ou publie cette librairie (pas aux projets qui la consomment — voir [`README.md`](README.md) pour ça).

## 1. Architecture

Projet Maven multi-module, pensé pour respecter la Clean Architecture (Dependency Inversion) :

```
jwt-toolkit/                    (pom parent — packaging "pom", pas de code)
├── jwt-core/                   (Java pur, aucune dépendance Spring)
└── jwt-spring-boot-starter/    (auto-configuration Spring Boot, dépend de jwt-core)
```

**Pourquoi cette séparation ?** `jwt-core` contient toute la logique métier (signature, validation, claims). Il doit rester compilable et testable sans jamais importer une classe Spring — c'est ce qui permettra un jour un module `jwt-quarkus-extension` sans toucher au core. `jwt-spring-boot-starter` n'est qu'une couche d'assemblage (beans, `@ConfigurationProperties`) au-dessus.

### Packages de `jwt-core`

| Package      | Contenu                                                                                             |
| ------------ | --------------------------------------------------------------------------------------------------- |
| `algorithm`  | `JwtAlgorithm` — métadonnées des algorithmes (famille, taille de clé min.)                          |
| `key`        | `SigningKeyProvider` (Strategy) + implémentations Hmac/Rsa/Ec                                       |
| `claims`     | `JwtClaims` (lecture typée), `JwtClaimsBuilder`, `ClaimsCustomizer` (point d'extension Open/Closed) |
| `token`      | `JwtTokenSpec` (builder), `JwtTokenService` (port) + `DefaultJwtTokenService` (impl jjwt)           |
| `revocation` | `TokenRevocationPort` (port) + `NoOpTokenRevocationPort` (implémentation par défaut)                |
| `exception`  | Hiérarchie propre à la librairie — jjwt ne fuite jamais vers l'appelant                             |

**Principe non négociable** : `DefaultJwtTokenService` est le **seul** endroit du core qui importe `io.jsonwebtoken.*`. Toute nouvelle fonctionnalité doit continuer à exposer des types `jwt-core` (`JwtClaims`, `JwtValidationException`...) à l'appelant, jamais des types jjwt — c'est la couche anti-corruption qui permettrait de changer d'implémentation JWT sans casser les consommateurs.

### Packages de `jwt-spring-boot-starter`

| Package         | Contenu                                                                                           |
| --------------- | ------------------------------------------------------------------------------------------------- |
| `autoconfigure` | `JwtProperties` (`jwt.*`), `JwtAutoConfiguration`, `JwtSecurityAutoConfiguration`                 |
| `security`      | `JwtAuthenticationFilter`, `JwtAuthenticationConverter` (intégration Spring Security optionnelle) |

Chaque bean d'auto-configuration est `@ConditionalOnMissingBean` : un consommateur peut remplacer n'importe quelle pièce (provider de clé, révocation, horloge) sans forker la librairie.

## 2. Build & tests

```bash
mvn clean install
```

Construit les 2 modules dans l'ordre (`jwt-core` avant `jwt-spring-boot-starter`, car ce dernier en dépend) et exécute tous les tests. Pour un seul module :

```bash
mvn -pl jwt-core clean test
```

### Ajouter un test

- `jwt-core` : JUnit 5 + AssertJ, aucun mock nécessaire (tout est déterministe via `Clock.fixed(...)`).
- `jwt-spring-boot-starter` : `ApplicationContextRunner` pour tester l'auto-configuration sans démarrer un vrai serveur (voir `JwtAutoConfigurationTest`).

## 3. Pièges Maven déjà rencontrés (à ne pas reproduire)

Deux bugs réels ont été corrigés pendant la mise au point de `jwt-spring-boot-starter` — utile de les documenter pour ne pas les réintroduire :

### a) Ne jamais déclarer deux fois la même dépendance avec un `<scope>` différent

```xml
<!-- ❌ NE PAS FAIRE -->
<dependency><groupId>org.springframework.security</groupId><artifactId>spring-security-web</artifactId><optional>true</optional></dependency>
...
<dependency><groupId>org.springframework.security</groupId><artifactId>spring-security-web</artifactId><scope>test</scope></dependency>
```

Maven avertit ("duplicate declaration of version") et peut ne conserver que la seconde déclaration, cassant la compilation du code principal. **Une seule déclaration par dépendance** ; si elle doit être visible en `test`, la déclaration `compile`/`optional` suffit déjà (elle couvre `src/test` aussi).

### b) Les scopes `provided`/`test` ne sont jamais transitifs

`spring-web` (dont dépend `spring-security-web`) déclare `jakarta.servlet-api` en scope `provided`. Ce scope ne se propage jamais aux consommateurs, même indirects. Résultat : `OncePerRequestFilter` (utilisé par `JwtAuthenticationFilter`) est bien résolu, mais son besoin de `jakarta.servlet.Filter` ne l'est pas.

**Règle générale** : dès qu'une classe de ce module importe directement un package qui provient d'une dépendance _transitive_ en scope `provided`/`test`/`runtime`, il faut la redéclarer explicitement dans ce `pom.xml`. C'est pourquoi `jwt-spring-boot-starter/pom.xml` déclare explicitement, en plus de `spring-security-web`/`spring-security-core` :

```xml
<dependency><groupId>jakarta.servlet</groupId><artifactId>jakarta.servlet-api</artifactId><optional>true</optional></dependency>
<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><optional>true</optional></dependency>
```

**Si vous ajoutez un nouvel import direct** dans `jwt-spring-boot-starter` (ex : une nouvelle classe Spring Security), vérifiez d'abord avec `mvn dependency:tree -Dverbose` que le package importé est bien accessible en scope `compile`/`optional` — pas seulement présent quelque part dans l'arbre.

## 4. CI/CD

- **`.github/workflows/ci.yml`** : build + tests sur Java 17 et 21 à chaque push/PR sur `main`. C'est la vérification de compilation qui fait foi (ce sandbox de développement n'a pas accès à Maven Central).
- **`.github/workflows/release.yml`** : déclenché par un tag `vX.Y.Z`. Build signé GPG + publication vers Maven Central **et** GitHub Packages en une seule commande (détails et secrets requis : section 5 ci-dessous).
- **`.github/dependabot.yml`** : mises à jour hebdomadaires des dépendances Maven et des actions GitHub.

## 5. Processus de release — pas à pas complet

Le projet publie vers **deux dépôts en une seule commande** (`mvn -P release deploy`) :

- **Maven Central**, via le profil `release` (`central-publishing-maven-plugin`) — dépôt public, aucune authentification requise pour le consommer.
- **GitHub Packages**, via `<distributionManagement>` dans le `pom.xml` racine (actif par défaut, indépendamment du profil) — nécessite une authentification même en lecture.

Le `groupId` est `io.github.sidymohamed12` : ce namespace se vérifie automatiquement via votre compte GitHub, sans avoir besoin de posséder un nom de domaine (contrairement à un `groupId` type `com.sidymohamed12.jwt`, qui aurait exigé un enregistrement DNS TXT sur `sidymohamed12.com`).

### 5.1 Compte Maven Central (une seule fois)

1. Créer un compte sur [central.sonatype.com](https://central.sonatype.com).
2. **Vérifier le namespace** `io.github.sidymohamed12` : Sonatype propose une vérification automatique en se connectant avec le compte GitHub `sidymohamed12` (OAuth) — pas de fichier à déposer, pas de DNS à configurer.
3. Générer un **User Token** : `Account` (menu en haut à droite) `> Generate User Token`. Notez le couple `username`/`password` généré (ce n'est pas votre mot de passe de compte).

### 5.2 Clé GPG (une seule fois)

Maven Central exige que chaque artefact soit signé.

```bash
gpg --full-generate-key
# Choisir RSA, 4096 bits, sans expiration (ou une longue durée)

gpg --list-secret-keys --keyid-format LONG
# Repérer l'ID de la clé (après "sec   rsa4096/")

gpg --keyserver keyserver.ubuntu.com --send-keys <KEY_ID>
# Publie la clé publique — Central vérifie sa présence sur un key-server

gpg --export-secret-keys --armor <KEY_ID> > private-key.asc
# Contenu à coller dans le secret GitHub GPG_PRIVATE_KEY (voir 5.3)
```

### 5.3 Secrets GitHub (une seule fois)

Dans `Settings > Secrets and variables > Actions` du dépôt :

| Secret             | Valeur                                           |
| ------------------ | ------------------------------------------------ |
| `CENTRAL_USERNAME` | Username du token généré en 5.1                  |
| `CENTRAL_PASSWORD` | Password du token généré en 5.1                  |
| `GPG_PRIVATE_KEY`  | Contenu complet de `private-key.asc` (5.2)       |
| `GPG_PASSPHRASE`   | Passphrase choisie à la génération de la clé GPG |

`GitHub Packages`, lui, n'a besoin d'**aucun secret supplémentaire** : le workflow utilise le `GITHUB_TOKEN` fourni automatiquement par Actions (voir le bloc `permissions: packages: write` dans `release.yml`).

### 5.4 Publier une version

```bash
# 1. Mettre à jour <version> dans les 3 pom.xml (racine + 2 modules) : 1.0.1-SNAPSHOT -> 1.0.1
# 2. Committer
git add .
git commit -m "Release 1.0.1"

# 3. Taguer et pousser
git tag v1.0.1
git push origin main --tags
```

Le tag `v1.0.1` déclenche `release.yml`, qui build, teste, signe et publie vers les deux dépôts. Suivre la progression dans l'onglet **Actions** du dépôt GitHub.

**Après publication sur Central** : les artefacts apparaissent d'abord dans le _staging repository_ du Central Publisher Portal. Avec `autoPublish=false` (configuré dans `pom.xml`), une validation manuelle est nécessaire : se connecter sur [central.sonatype.com](https://central.sonatype.com), onglet `Deployments`, vérifier que tout est vert, puis cliquer `Publish`. Repassez `autoPublish` à `true` dans le `pom.xml` une fois confiant dans le pipeline, pour publier automatiquement sans étape manuelle.

### 5.5 Publier manuellement en local (dépannage)

Si besoin de publier depuis votre machine plutôt que via CI, configurez `~/.m2/settings.xml` avec les mêmes credentials (serveurs `central`, `github`, `gpg.passphrase` — voir la structure générée dans `release.yml`), puis :

```bash
mvn -P release clean deploy
```

## 6. Conventions de code

- **Clean Architecture / SOLID** : `jwt-core` ne dépend d'aucun framework ; toute nouvelle abstraction (nouveau type de clé, nouvelle stratégie de révocation...) passe par une interface dans le port concerné avant d'écrire une implémentation.
- **Javadoc obligatoire** sur toute classe, méthode et champ public — y compris les `@param`/`@return`/`@throws`. C'est ce qui permet de générer une doc HTML fiable (`mvn javadoc:aggregate`) et d'onboarder rapidement un nouveau contributeur.
- **Pas de dépendance jjwt en dehors de `token/DefaultJwtTokenService.java`** dans `jwt-core` (cf. section 1).
- **Tests déterministes** : toujours injecter une `Clock` plutôt que `Clock.systemUTC()` en dur dans les tests.

## 7. Étapes suggérées pour la suite

- `flatten-maven-plugin` pour un versioning CI-friendly (`${revision}`), afin d'éviter d'éditer 3 fichiers à chaque release.
- Module `jwt-quarkus-extension` — `jwt-core` est déjà prêt, aucune dépendance à changer.
- Tests supplémentaires end-to-end EC (sur le modèle de `RsaEndToEndTest`).
