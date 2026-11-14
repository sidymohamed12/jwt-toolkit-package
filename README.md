# JWT Toolkit

Librairie Java de génération/validation de JWT **personnalisable**, en deux modules :

| Module                    | Dépend de Spring ? | Pour qui ?                                        |
| ------------------------- | ------------------ | ------------------------------------------------- |
| `jwt-core`                | Non                | Tout projet Java (Spring, Quarkus, batch, CLI...) |
| `jwt-spring-boot-starter` | Oui                | Projets Spring Boot — zéro boilerplate            |

> Vous développez ou maintenez cette librairie ? Voir [`CONTRIBUTING.md`](CONTRIBUTING.md) (architecture, build, CI/CD, publication).

## Installation

Disponible sur **Maven Central** (aucune configuration de dépôt nécessaire) et sur **GitHub Packages** (nécessite une authentification, même en lecture — voir note ci-dessous).

```xml
<!-- Projet non-Spring -->
<dependency>
    <groupId>io.github.sidymohamed12</groupId>
    <artifactId>jwt-core</artifactId>
    <version>1.1.0</version>
</dependency>

<!-- Projet Spring Boot (ramène jwt-core automatiquement) -->
<dependency>
    <groupId>io.github.sidymohamed12</groupId>
    <artifactId>jwt-spring-boot-starter</artifactId>
    <version>1.1.0</version>
</dependency>
```

> **Via GitHub Packages plutôt que Maven Central ?** GitHub exige une authentification pour _toute_ consommation d'un package Maven, même public. Ajoutez dans votre `pom.xml` :
>
> ```xml
> <repositories>
>     <repository>
>         <id>github</id>
>         <url>https://maven.pkg.github.com/sidymohamed12/jwt-toolkit-package</url>
>     </repository>
> </repositories>
> ```
>
> puis un serveur `github` dans votre `~/.m2/settings.xml` avec un token GitHub (scope `read:packages` suffit). Pour un usage "librairie partagée entre projets" sans friction, **Maven Central est recommandé** : aucune authentification requise pour la consommer.

## Démarrage rapide

### Sans Spring (`jwt-core` seul)

```java
SigningKeyProvider keyProvider = new HmacSigningKeyProvider(secret, JwtAlgorithm.HS256);
JwtTokenService jwtTokenService = new DefaultJwtTokenService(
        keyProvider, Clock.systemUTC(), List.of(), new NoOpTokenRevocationPort());

String token = jwtTokenService.generate(JwtTokenSpec.builder()
        .subject("user@example.com")
        .ttl(Duration.ofMinutes(15))
        .build());

JwtClaims claims = jwtTokenService.parse(token); // lève JwtValidationException si invalide
```

### Avec Spring Boot (`jwt-spring-boot-starter`)

```yaml
jwt:
  algorithm: HS256
  secret: ${JWT_SECRET} # >= 32 caractères pour HS256
  access-token-ttl: PT15M
  refresh-token-ttl: P7D
```

```java
@Service
public class AuthService {

    private final JwtTokenService jwtTokenService; // bean déjà disponible, rien à configurer

    public AuthService(JwtTokenService jwtTokenService) {
        this.jwtTokenService = jwtTokenService;
    }
}
```

## Personnaliser les champs (claims)

C'est le cœur de la librairie : chaque projet ajoute exactement les claims dont il a besoin, sans que `jwt-core` n'ait à les connaître à l'avance.

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

Lecture typée :

```java
JwtClaims claims = jwtTokenService.parse(token);
claims.subject();
claims.getUUID("entrepotId");
claims.getStringSet("roles");
```

### Claims globaux automatiques (`ClaimsCustomizer`)

Pour ajouter un champ à **tous** les tokens sans toucher au code appelant (ex : `issuer`, `env`) :

```java
@Bean
ClaimsCustomizer environmentClaimsCustomizer() {
    return builder -> builder.claim("env", "production").claim("iss", "senpharmaflow");
}
```

## Recettes : token simple vs. paire access/refresh

La librairie ne fait aucune hypothèse sur votre stratégie de tokens — c'est vous qui décidez en appelant `generate()` une ou deux fois.

**Token simple** (une seule durée de vie, un seul usage) :

```java
String token = jwtTokenService.generate(JwtTokenSpec.builder()
        .subject(user.getEmail())
        .ttl(Duration.ofHours(1))
        .build());
```

**Paire access + refresh** (pattern classique pour une session utilisateur longue) :

```java
String access = jwtTokenService.generate(JwtTokenSpec.builder()
        .subject(user.getEmail()).ttl(Duration.ofMinutes(15)).build());

String refresh = jwtTokenService.generate(JwtTokenSpec.builder()
        .subject(user.getEmail()).ttl(Duration.ofDays(7))
        .claim("type", "refresh")   // distingue le refresh d'un access token
        .build());
```

Côté vérification, avant d'honorer une demande de rafraîchissement :

```java
JwtClaims claims = jwtTokenService.parse(refreshToken);
if (!"refresh".equals(claims.getString("type").orElse(null))) {
    throw new IllegalArgumentException("Ce n'est pas un refresh token.");
}
```

## RSA / EC — vérification par plusieurs microservices

Un service central signe (clé privée), d'autres services ne font que vérifier (clé publique), sans jamais pouvoir forger de token.

```yaml
jwt:
  algorithm: RS256
  rsa:
    public-key: ${JWT_RSA_PUBLIC_KEY} # Base64 X509, obligatoire
    private-key: ${JWT_RSA_PRIVATE_KEY} # Base64 PKCS8, uniquement côté service émetteur
```

Un microservice qui ne fait que **vérifier** omet `jwt.rsa.private-key` : `RsaSigningKeyProvider` bascule automatiquement en mode vérification seule (toute tentative de signature lève une `IllegalStateException` explicite).

## Algorithme strict

L'algorithme configuré (`jwt.algorithm`) est imposé **des deux côtés** :

- **à la signature** : le token est toujours signé avec l'algorithme configuré, jamais avec un algorithme déduit de la taille de la clé (un secret de 48 octets configuré en `HS256` produit bien un token `HS256`, pas `HS384`) ;
- **à la validation** : l'en-tête `alg` du token doit être **exactement** cet algorithme. Un token `HS512` est refusé par un service `HS256`, un token `RS512` par un service `RS256`, et un token HMAC par un service RSA/EC (attaque « algorithm confusion »). Les tokens non signés (`alg: none`) sont toujours refusés.

> **Mise à jour depuis 1.0.x** : si votre secret HMAC est plus long que le minimum de l'algorithme configuré (ex. 48 octets en `HS256`), les versions 1.0.x signaient en réalité avec un algorithme plus fort (`HS384`). Ces tokens sont refusés à partir de 1.1.0 : les utilisateurs concernés devront se reconnecter une fois.

## Rotation des clés (`kid`)

Changer de clé sans déconnecter tout le monde : la clé **active** signe les nouveaux tokens (son identifiant est écrit dans l'en-tête `kid`), les clés **précédentes** ne servent qu'à vérifier les tokens encore en circulation.

```yaml
jwt:
  algorithm: HS256
  secret: ${JWT_SECRET} # clé active
  rotation:
    active-key-id: "2026-11"
    previous-keys:
      - key-id: "2026-10"
        secret: ${JWT_SECRET_PREVIOUS} # vérification seule
      # RSA/EC : public-key à la place de secret ; algorithm optionnel (défaut : jwt.algorithm)
```

Règles de vérification :

| Token reçu                         | Clé utilisée                                  |
| ---------------------------------- | --------------------------------------------- |
| `kid` de la clé active ou précédente | cette clé (avec **son** algorithme, strict) |
| sans `kid`                         | la clé active                                 |
| `kid` inconnu                      | aucune → token refusé                         |

Sans `jwt.rotation`, le comportement est celui de la version 1.0.x : une seule clé, pas de `kid`.

**Procédure de rotation recommandée**

1. **Une seule fois**, si vos tokens actuels n'ont pas de `kid` : donnez un identifiant à la clé actuelle (`active-key-id: "2026-10"`, même secret) et déployez. Attendez la durée de vie d'un refresh token (7 jours par défaut) pour que tous les tokens en circulation portent ce `kid`.
2. Mettez la nouvelle clé dans `jwt.secret`, changez `active-key-id`, et déplacez l'ancienne clé dans `previous-keys`. Déployez.
3. Après la durée de vie d'un refresh token, retirez l'ancienne clé de `previous-keys`.

Sans Spring :

```java
SigningKeyRing ring = SigningKeyRing.builder()
        .active("2026-11", new HmacSigningKeyProvider(newSecret, JwtAlgorithm.HS256))
        .previous("2026-10", new HmacSigningKeyProvider(oldSecret, JwtAlgorithm.HS256))
        .build();

JwtTokenService service = new DefaultJwtTokenService(ring, Clock.systemUTC(), List.of(), null);
```

## Révocation de tokens (liste noire)

> ⚠️ **Par défaut, la librairie ne révoque aucun token.** Sans configuration
> supplémentaire, un token signé reste valide jusqu'à sa date d'expiration
> naturelle (`exp`) — se déconnecter, changer de mot de passe, ou appeler
> `revoke()` n'a **aucun effet concret** tant qu'aucun `TokenRevocationPort`
> personnalisé n'est branché. C'est un choix assumé, pas un oubli : voir
> `NoOpTokenRevocationPortTest` et `DefaultJwtTokenServiceTest` (module
> `jwt-core`) pour ce comportement testé et documenté noir sur blanc.

Concrètement :

```java
TokenRevocationPort port = new NoOpTokenRevocationPort(); // celui utilisé par défaut

port.revoke(token, Duration.ofMinutes(15)); // ne fait rien
port.isRevoked(token);                       // toujours false, quel que soit le token
```

Si la révocation immédiate est un besoin de sécurité de votre projet (déconnexion forcée, bannissement d'un compte...), branchez votre propre implémentation, par exemple avec Redis :

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

Ce bean, dès qu'il est déclaré dans votre application, remplace automatiquement `NoOpTokenRevocationPort` (grâce à `@ConditionalOnMissingBean` côté starter). Une fois branché, `jwtTokenService.parse(token)` consulte systématiquement `isRevoked(token)` avant de valider signature/expiration.

## Intégration Spring Security (optionnelle)

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

## Référence rapide des classes principales

| Classe                                                   | Rôle                                                     |
| -------------------------------------------------------- | -------------------------------------------------------- |
| `JwtTokenService` / `DefaultJwtTokenService`             | Générer/valider des tokens                               |
| `JwtTokenSpec` (+ builder)                               | Décrire le token à générer (sujet, ttl, claims)          |
| `JwtClaims`                                              | Lire les claims d'un token décodé, avec accesseurs typés |
| `SigningKeyProvider` (Hmac/Rsa/Ec)                       | Fournir les clés de signature/vérification               |
| `SigningKeyRing`                                         | Rotation : clé active + clés précédentes, par `kid`      |
| `ClaimsCustomizer`                                       | Ajouter des claims à tous les tokens automatiquement     |
| `TokenRevocationPort`                                    | Brancher une liste noire (Redis, DB...)                  |
| `JwtAuthenticationFilter` / `JwtAuthenticationConverter` | Intégration Spring Security (starter uniquement)         |

## Licence

MIT — voir [`LICENSE`](LICENSE).
