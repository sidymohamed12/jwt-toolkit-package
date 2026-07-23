# JWT Toolkit

Librairie Java de génération/validation de JWT **personnalisable**, conçue pour être publiée sur Maven et réutilisée sur plusieurs projets.

Deux modules, respectant le principe de Dependency Inversion (Clean Architecture) :

| Module | Dépend de Spring ? | Rôle |
|---|---|---|
| `jwt-core` | Non | Génération, validation, personnalisation des claims. Utilisable dans n'importe quelle app Java (Spring, Quarkus, batch, CLI...). |
| `jwt-spring-boot-starter` | Oui | Auto-configuration Spring Boot (`jwt.*`), zéro boilerplate, intégration Spring Security optionnelle. |

## 1. Concepts clés

### `SigningKeyProvider` — abstraction des clés (Strategy)
```
HmacSigningKeyProvider   // secret partagé (HS256/384/512)
RsaSigningKeyProvider    // paire de clés RSA (RS256/384/512)
EcSigningKeyProvider     // paire de clés EC  (ES256/384/512)
```
Chaque implémentation valide la taille minimale de clé/secret à la construction et échoue tôt avec un message explicite.

### `JwtTokenSpec` — personnalisation des champs
```java
JwtTokenSpec spec = JwtTokenSpec.builder()
        .subject(user.getEmail())
        .ttl(Duration.ofMinutes(15))
        .claim("roles", Set.of("ADMIN", "GESTIONNAIRE"))
        .claim("entrepotId", entrepotId)       // UUID accepté directement
        .claim("tenantId", tenantId)
        .autoTokenId()                          // jti aléatoire
        .build();

String token = jwtTokenService.generate(spec);
```

### `ClaimsCustomizer` — claims globaux (Open/Closed)
Pour ajouter un champ à **tous** les tokens sans toucher au code appelant (ex : `issuer`, `env`) :
```java
@Bean
ClaimsCustomizer environmentClaimsCustomizer() {
    return builder -> builder.claim("env", "production").claim("iss", "senpharmaflow");
}
```

### `TokenRevocationPort` — révocation plug-able
```java
public interface TokenRevocationPort {
    void revoke(String token, Duration ttl);
    boolean isRevoked(String token);
}
```
Par défaut : `NoOpTokenRevocationPort` (aucune révocation). Exemple de branchement Redis dans votre application :
```java
@Component
public class RedisTokenRevocationPort implements TokenRevocationPort {

    private final StringRedisTemplate redis;
    private static final String PREFIX = "jwt:revoked:";

    public RedisTokenRevocationPort(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public void revoke(String token, Duration ttl) {
        if (ttl.isNegative() || ttl.isZero()) return;
        redis.opsForValue().set(PREFIX + sha256(token), "1", ttl);
    }

    @Override
    public boolean isRevoked(String token) {
        return Boolean.TRUE.equals(redis.hasKey(PREFIX + sha256(token)));
    }

    private String sha256(String input) { /* ... */ }
}
```
Ce bean, dès qu'il est déclaré dans votre application, remplace automatiquement le `NoOpTokenRevocationPort` (`@ConditionalOnMissingBean`).

### `JwtClaims` — lecture typée
```java
JwtClaims claims = jwtTokenService.parse(token);
claims.subject();
claims.getUUID("entrepotId");
claims.getStringSet("roles");
claims.getInstant("someTimestampClaim");
```

## 2. Utilisation — `jwt-core` seul (sans Spring)

```java
SigningKeyProvider keyProvider = new HmacSigningKeyProvider(secret, JwtAlgorithm.HS256);
JwtTokenService jwtTokenService = new DefaultJwtTokenService(
        keyProvider, Clock.systemUTC(), List.of(), new NoOpTokenRevocationPort());

String token = jwtTokenService.generate(JwtTokenSpec.builder()
        .subject("user@example.com").ttl(Duration.ofMinutes(15)).build());

JwtClaims claims = jwtTokenService.parse(token); // lève JwtValidationException si invalide
```

## 3. Utilisation — `jwt-spring-boot-starter`

Ajoutez la dépendance, puis configurez :

```yaml
jwt:
  algorithm: HS256
  secret: ${JWT_SECRET}          # >= 32 caractères pour HS256
  access-token-ttl: PT15M
  refresh-token-ttl: P7D
```

Le bean `JwtTokenService` est disponible immédiatement — aucune classe de configuration à écrire.

### RSA / EC (vérification par plusieurs microservices)
```yaml
jwt:
  algorithm: RS256
  rsa:
    public-key: ${JWT_RSA_PUBLIC_KEY}     # Base64 X509, obligatoire
    private-key: ${JWT_RSA_PRIVATE_KEY}   # Base64 PKCS8, uniquement côté service émetteur
```
Un microservice qui ne fait que **vérifier** les tokens omet `jwt.rsa.private-key` : `RsaSigningKeyProvider` bascule automatiquement en mode vérification seule (toute tentative de signature lève une `IllegalStateException` explicite).

### Intégration Spring Security (optionnelle)
Fournissez un `JwtAuthenticationConverter` pour activer automatiquement `JwtAuthenticationFilter` :
```java
@Bean
JwtAuthenticationConverter jwtAuthenticationConverter(UserDetailsService uds) {
    return claims -> {
        UserDetails user = uds.loadUserByUsername(claims.subject());
        return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
    };
}
```
Puis, dans votre `SecurityFilterChain` :
```java
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtFilter) throws Exception {
    return http
        .csrf(AbstractHttpConfigurer::disable)
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .build();
}
```

## 4. Build local

```bash
mvn clean verify
```

## 5. Publier sur Maven

Deux options courantes :

### Option A — GitHub Packages (le plus rapide à mettre en place)
1. Ajoutez dans le `pom.xml` racine :
```xml
<distributionManagement>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/sidymohamed12/jwt-toolkit</url>
    </repository>
</distributionManagement>
```
2. Dans `~/.m2/settings.xml`, un serveur `github` avec un token GitHub (`write:packages`).
3. `mvn deploy`
4. Dans vos futurs projets, ajoutez le repository GitHub Packages et la dépendance normalement.

### Option B — Maven Central (le plus universel, pas besoin de token GitHub côté consommateur)
1. Créer un compte sur [central.sonatype.com](https://central.sonatype.com) et vérifier la propriété du `groupId` (`com.sidymohamed12` → nécessite de prouver la propriété du compte GitHub `sidymohamed12`, car ce n'est pas un nom de domaine).
2. Générer une paire de clés GPG (`gpg --gen-key`) et la publier sur un key-server.
3. Configurer `~/.m2/settings.xml` avec un serveur `central` (token Sonatype) et vos infos GPG.
4. `mvn -P release clean deploy`
5. Valider/publier le "staging repository" sur le Central Publisher Portal.

> ⚠️ Le `groupId` actuel (`com.sidymohamed12.jwt`) est un point de départ à confirmer avant toute publication réelle : Maven Central exige de prouver qu'on contrôle le namespace choisi.

## 6. Intégration continue (CI/CD)

Deux workflows GitHub Actions sont fournis dans `.github/workflows/` :

- **`ci.yml`** : à chaque push/PR sur `main`, build + tests sur Java 17 et 21 (matrice), publication des rapports de tests. C'est ici — pas dans ce sandbox, qui n'a pas accès à Maven Central — que la compilation est réellement vérifiée en continu.
- **`release.yml`** : déclenché par un tag `vX.Y.Z` poussé sur le dépôt. Construit, signe (GPG) et publie sur Maven Central via le profil `release` (`central-publishing-maven-plugin`).

Secrets GitHub requis pour `release.yml` (`Settings > Secrets and variables > Actions`) :

| Secret | Origine |
|---|---|
| `CENTRAL_USERNAME` / `CENTRAL_PASSWORD` | Token généré sur [central.sonatype.com](https://central.sonatype.com) (Account > Generate User Token) |
| `GPG_PRIVATE_KEY` | `gpg --export-secret-keys --armor <votre-id>` |
| `GPG_PASSPHRASE` | Passphrase de cette clé GPG |

Un `dependabot.yml` maintient également les dépendances Maven et les actions GitHub à jour chaque semaine.

**Pour publier une version** : mettez à jour `<version>` dans les 3 `pom.xml` (racine + 2 modules), committez, taguez (`git tag v1.0.0 && git push --tags`) — le workflow `release.yml` s'occupe du reste.

## 7. Prochaines étapes suggérées

- Ajouter le `flatten-maven-plugin` si vous voulez un versioning CI-friendly (`${revision}`), pour éviter d'éditer 3 fichiers à chaque release.
- Ajouter un module `jwt-quarkus-extension` si un projet futur utilise Quarkus — `jwt-core` est déjà prêt pour ça, aucune dépendance à changer.
- Une fois le dépôt GitHub créé, lancer `mvn clean verify` en local (ou laisser `ci.yml` le faire) pour la toute première vérification de compilation réelle.
