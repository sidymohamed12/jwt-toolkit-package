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

| Package | Contenu |
|---|---|
| `algorithm` | `JwtAlgorithm` — métadonnées des algorithmes (famille, taille de clé min.) |
| `key` | `SigningKeyProvider` (Strategy) + implémentations Hmac/Rsa/Ec |
| `claims` | `JwtClaims` (lecture typée), `JwtClaimsBuilder`, `ClaimsCustomizer` (point d'extension Open/Closed) |
| `token` | `JwtTokenSpec` (builder), `JwtTokenService` (port) + `DefaultJwtTokenService` (impl jjwt) |
| `revocation` | `TokenRevocationPort` (port) + `NoOpTokenRevocationPort` (implémentation par défaut) |
| `exception` | Hiérarchie propre à la librairie — jjwt ne fuite jamais vers l'appelant |

**Principe non négociable** : `DefaultJwtTokenService` est le **seul** endroit du core qui importe `io.jsonwebtoken.*`. Toute nouvelle fonctionnalité doit continuer à exposer des types `jwt-core` (`JwtClaims`, `JwtValidationException`...) à l'appelant, jamais des types jjwt — c'est la couche anti-corruption qui permettrait de changer d'implémentation JWT sans casser les consommateurs.

### Packages de `jwt-spring-boot-starter`

| Package | Contenu |
|---|---|
| `autoconfigure` | `JwtProperties` (`jwt.*`), `JwtAutoConfiguration`, `JwtSecurityAutoConfiguration` |
| `security` | `JwtAuthenticationFilter`, `JwtAuthenticationConverter` (intégration Spring Security optionnelle) |

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

**Règle générale** : dès qu'une classe de ce module importe directement un package qui provient d'une dépendance *transitive* en scope `provided`/`test`/`runtime`, il faut la redéclarer explicitement dans ce `pom.xml`. C'est pourquoi `jwt-spring-boot-starter/pom.xml` déclare explicitement, en plus de `spring-security-web`/`spring-security-core` :
```xml
<dependency><groupId>jakarta.servlet</groupId><artifactId>jakarta.servlet-api</artifactId><optional>true</optional></dependency>
<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><optional>true</optional></dependency>
```
**Si vous ajoutez un nouvel import direct** dans `jwt-spring-boot-starter` (ex : une nouvelle classe Spring Security), vérifiez d'abord avec `mvn dependency:tree -Dverbose` que le package importé est bien accessible en scope `compile`/`optional` — pas seulement présent quelque part dans l'arbre.

## 4. CI/CD

- **`.github/workflows/ci.yml`** : build + tests sur Java 17 et 21 à chaque push/PR sur `main`. C'est la vérification de compilation qui fait foi (ce sandbox de développement n'a pas accès à Maven Central).
- **`.github/workflows/release.yml`** : déclenché par un tag `vX.Y.Z`. Build signé GPG + publication Maven Central via le profil `release` (`central-publishing-maven-plugin`).
- **`.github/dependabot.yml`** : mises à jour hebdomadaires des dépendances Maven et des actions GitHub.

### Secrets requis pour `release.yml`

| Secret | Origine |
|---|---|
| `CENTRAL_USERNAME` / `CENTRAL_PASSWORD` | Token généré sur [central.sonatype.com](https://central.sonatype.com) (Account > Generate User Token) |
| `GPG_PRIVATE_KEY` | `gpg --export-secret-keys --armor <votre-id>` |
| `GPG_PASSPHRASE` | Passphrase de cette clé GPG |

## 5. Processus de release

1. Mettre à jour `<version>` dans les 3 `pom.xml` (racine + 2 modules).
2. Committer, taguer : `git tag v1.0.0 && git push --tags`.
3. `release.yml` construit, signe et publie automatiquement.

### Option alternative : GitHub Packages (plus rapide à mettre en place, sans vérification de namespace)
```xml
<distributionManagement>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/sidymohamed12/jwt-toolkit</url>
    </repository>
</distributionManagement>
```
Nécessite un serveur `github` dans `~/.m2/settings.xml` avec un token GitHub (`write:packages`), puis `mvn deploy`.

> ⚠️ Le `groupId` actuel (`com.sidymohamed12.jwt`) doit être confirmé avant toute publication réelle sur Maven Central : il faut prouver la propriété du namespace (compte GitHub `sidymohamed12`).

## 6. Conventions de code

- **Clean Architecture / SOLID** : `jwt-core` ne dépend d'aucun framework ; toute nouvelle abstraction (nouveau type de clé, nouvelle stratégie de révocation...) passe par une interface dans le port concerné avant d'écrire une implémentation.
- **Javadoc obligatoire** sur toute classe, méthode et champ public — y compris les `@param`/`@return`/`@throws`. C'est ce qui permet de générer une doc HTML fiable (`mvn javadoc:aggregate`) et d'onboarder rapidement un nouveau contributeur.
- **Pas de dépendance jjwt en dehors de `token/DefaultJwtTokenService.java`** dans `jwt-core` (cf. section 1).
- **Tests déterministes** : toujours injecter une `Clock` plutôt que `Clock.systemUTC()` en dur dans les tests.

## 7. Étapes suggérées pour la suite

- `flatten-maven-plugin` pour un versioning CI-friendly (`${revision}`), afin d'éviter d'éditer 3 fichiers à chaque release.
- Module `jwt-quarkus-extension` — `jwt-core` est déjà prêt, aucune dépendance à changer.
- Tests supplémentaires end-to-end EC (sur le modèle de `RsaEndToEndTest`).
