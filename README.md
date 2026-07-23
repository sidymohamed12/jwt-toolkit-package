# JWT Toolkit

Librairie Java de génération/validation de JWT **personnalisable**, en deux modules :

| Module                    | Dépend de Spring ? | Pour qui ?                                        |
| ------------------------- | ------------------ | ------------------------------------------------- |
| `jwt-core`                | Non                | Tout projet Java (Spring, Quarkus, batch, CLI...) |
| `jwt-spring-boot-starter` | Oui                | Projets Spring Boot — zéro boilerplate            |

> Vous développez ou maintenez cette librairie ? Voir [`CONTRIBUTING.md`](CONTRIBUTING.md) (architecture, build, CI/CD, publication).

## Installation

```xml
<!-- Projet non-Spring -->
<dependency>
    <groupId>com.sidymohamed12.jwt</groupId>
    <artifactId>jwt-core</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>

<!-- Projet Spring Boot (ramène jwt-core automatiquement) -->
<dependency>
    <groupId>com.sidymohamed12.jwt</groupId>
    <artifactId>jwt-spring-boot-starter</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

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

## Révocation de tokens (liste noire)

Par défaut : `NoOpTokenRevocationPort` (aucune révocation). Branchez votre propre implémentation, par exemple avec Redis :

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

Ce bean, dès qu'il est déclaré, remplace automatiquement `NoOpTokenRevocationPort`.

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
| `ClaimsCustomizer`                                       | Ajouter des claims à tous les tokens automatiquement     |
| `TokenRevocationPort`                                    | Brancher une liste noire (Redis, DB...)                  |
| `JwtAuthenticationFilter` / `JwtAuthenticationConverter` | Intégration Spring Security (starter uniquement)         |

## Licence

MIT — voir [`LICENSE`](LICENSE).
