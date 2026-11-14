package com.sidymohamed12.jwt.core.token;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;
import com.sidymohamed12.jwt.core.claims.ClaimsCustomizer;
import com.sidymohamed12.jwt.core.claims.JwtClaims;
import com.sidymohamed12.jwt.core.claims.JwtClaimsBuilder;
import com.sidymohamed12.jwt.core.exception.JwtExpiredException;
import com.sidymohamed12.jwt.core.exception.JwtGenerationException;
import com.sidymohamed12.jwt.core.exception.JwtValidationException;
import com.sidymohamed12.jwt.core.key.SigningKeyProvider;
import com.sidymohamed12.jwt.core.key.SigningKeyRing;
import com.sidymohamed12.jwt.core.revocation.TokenRevocationPort;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithm;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Implémentation par défaut de {@link JwtTokenService}, basée sur
 * <a href="https://github.com/jwtk/jjwt">jjwt</a>.
 * <p>
 * jjwt reste un détail d'implémentation confiné à ce package : les types
 * exposés à l'appelant ({@link JwtClaims}, {@link JwtValidationException})
 * sont ceux de la librairie, jamais ceux de jjwt (Dependency Inversion /
 * anti-corruption layer). Remplacer jjwt par une autre implémentation JWT
 * à l'avenir n'impacterait donc aucun code consommateur.
 *
 * <h2>Algorithme strict</h2>
 * À la génération, le token est toujours signé avec l'algorithme
 * <strong>configuré</strong> ({@link SigningKeyProvider#algorithm()}), jamais
 * avec un algorithme déduit de la taille de la clé. À la validation, l'en-tête
 * {@code alg} du token doit être <strong>exactement</strong> l'algorithme de la
 * clé désignée : un token HS512 est refusé par un service HS256, un token RS512
 * par un service RS256, un token HMAC par un service RSA/EC, etc.
 *
 * <h2>Rotation des clés</h2>
 * Construit avec un {@link SigningKeyRing}, le service signe avec la clé active
 * (son {@code kid} est écrit dans l'en-tête) et vérifie chaque token avec la
 * clé désignée par son {@code kid} : les tokens émis avant une rotation restent
 * valides jusqu'à leur expiration, tant que l'ancienne clé est déclarée comme
 * clé précédente.
 */
public final class DefaultJwtTokenService implements JwtTokenService {

    private static final String NOT_SUPPORTED = "Algorithme non supporté : ";

    private final SigningKeyRing keyRing;
    private final Clock clock;
    private final List<ClaimsCustomizer> claimsCustomizers;
    private final TokenRevocationPort revocationPort;

    /**
     * @param signingKeyProvider fournit les clés de signature/vérification
     * @param clock              horloge utilisée pour {@code iat}/{@code exp} et la
     *                           validation de l'expiration
     *                           (injectable pour les tests ;
     *                           {@code Clock.systemUTC()} en production)
     * @param claimsCustomizers  claims globaux appliqués à chaque génération, dans
     *                           l'ordre de la liste
     *                           (peut être {@code null}, équivalent à une liste
     *                           vide)
     * @param revocationPort     vérifié avant chaque {@link #parse(String)} ;
     *                           {@code null} désactive la vérification
     */
    public DefaultJwtTokenService(SigningKeyProvider signingKeyProvider, Clock clock,
            List<ClaimsCustomizer> claimsCustomizers, TokenRevocationPort revocationPort) {
        this(SigningKeyRing.of(signingKeyProvider), clock, claimsCustomizers, revocationPort);
    }

    /**
     * Variante avec rotation de clés.
     *
     * @param keyRing           clé active (signature) et clés précédentes
     *                          (vérification seule), indexées par {@code kid}
     * @param clock             voir
     *                          {@link #DefaultJwtTokenService(SigningKeyProvider, Clock, List, TokenRevocationPort)}
     * @param claimsCustomizers idem
     * @param revocationPort    idem
     */
    public DefaultJwtTokenService(SigningKeyRing keyRing, Clock clock,
            List<ClaimsCustomizer> claimsCustomizers, TokenRevocationPort revocationPort) {
        this.keyRing = Objects.requireNonNull(keyRing, "keyRing ne peut pas être null");
        this.clock = clock;
        this.claimsCustomizers = claimsCustomizers == null ? List.of() : List.copyOf(claimsCustomizers);
        this.revocationPort = revocationPort;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Applique d'abord les {@link ClaimsCustomizer} enregistrés, puis les claims
     * explicites du {@code spec} (qui priment donc en cas de collision de nom).
     */
    @Override
    public String generate(JwtTokenSpec spec) {
        Instant now = Instant.now(clock);
        Instant expiration = now.plus(spec.ttl());

        Map<String, Object> claims = new HashMap<>();
        if (!claimsCustomizers.isEmpty()) {
            JwtClaimsBuilder builder = new JwtClaimsBuilder();
            claimsCustomizers.forEach(customizer -> customizer.customize(builder));
            claims.putAll(builder.build());
        }
        claims.putAll(spec.claims()); // les claims explicites du spec priment sur les claims globaux

        try {
            var jwtBuilder = Jwts.builder()
                    .subject(spec.subject())
                    .claims(claims)
                    .issuedAt(Date.from(now))
                    .expiration(Date.from(expiration));

            if (spec.tokenId() != null) {
                jwtBuilder.id(spec.tokenId());
            }
            keyRing.activeKeyId().ifPresent(kid -> jwtBuilder.header().keyId(kid).and());

            return sign(jwtBuilder, keyRing.active()).compact();
        } catch (RuntimeException e) {
            throw new JwtGenerationException("Échec de génération du JWT : " + e.getMessage(), e);
        }
    }

    /**
     * {@inheritDoc}
     * <p>
     * Vérifie d'abord la révocation
     * ({@link TokenRevocationPort#isRevoked(String)}), puis
     * la signature et l'expiration.
     */
    @Override
    public JwtClaims parse(String token) throws JwtValidationException {
        if (revocationPort != null && revocationPort.isRevoked(token)) {
            throw new JwtValidationException("Token révoqué.");
        }
        try {
            Claims claims = parser().parseSignedClaims(token).getPayload();
            return toJwtClaims(claims);
        } catch (ExpiredJwtException e) {
            throw new JwtExpiredException("Token expiré.", e);
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtValidationException("Token invalide : " + e.getMessage(), e);
        }
    }

    @Override
    public boolean isValid(String token) {
        try {
            parse(token);
            return true;
        } catch (JwtValidationException e) {
            return false;
        }
    }

    @Override
    public boolean isExpired(String token) {
        try {
            parser().parseSignedClaims(token);
            return false;
        } catch (ExpiredJwtException e) {
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            // Token invalide autrement (signature, format) : non exploitable, traité comme
            // expiré
            return true;
        }
    }

    /**
     * Signe avec l'algorithme <strong>explicitement</strong> configuré sur la clé
     * (sans cela, jjwt choisirait l'algorithme d'après la taille de la clé : un
     * secret de 48 octets configuré en HS256 produirait un token HS384).
     */
    private static JwtBuilder sign(JwtBuilder builder, SigningKeyProvider provider) {
        JwtAlgorithm algorithm = provider.algorithm();
        Key key = provider.signingKey();
        if (algorithm.isHmac() && key instanceof SecretKey secretKey) {
            return builder.signWith(secretKey, macAlgorithm(algorithm));
        }
        if (algorithm.isAsymmetric() && key instanceof PrivateKey privateKey) {
            return builder.signWith(privateKey, signatureAlgorithm(algorithm));
        }
        throw new IllegalStateException(
                "Clé de signature incompatible avec l'algorithme " + algorithm + " : " + key.getClass());
    }

    private static MacAlgorithm macAlgorithm(JwtAlgorithm algorithm) {
        return switch (algorithm) {
            case HS256 -> Jwts.SIG.HS256;
            case HS384 -> Jwts.SIG.HS384;
            case HS512 -> Jwts.SIG.HS512;
            default -> throw new IllegalArgumentException(NOT_SUPPORTED + algorithm);
        };
    }

    private static SignatureAlgorithm signatureAlgorithm(JwtAlgorithm algorithm) {
        return switch (algorithm) {
            case RS256 -> Jwts.SIG.RS256;
            case RS384 -> Jwts.SIG.RS384;
            case RS512 -> Jwts.SIG.RS512;
            case ES256 -> Jwts.SIG.ES256;
            case ES384 -> Jwts.SIG.ES384;
            case ES512 -> Jwts.SIG.ES512;
            default -> throw new IllegalArgumentException(NOT_SUPPORTED + algorithm);
        };
    }

    /**
     * Construit un parseur jjwt dont la clé de vérification est choisie par
     * {@link StrictKeyLocator} (lookup par {@code kid} + algorithme strict).
     */
    private JwtParser parser() {
        return Jwts.parser()
                .clock(() -> Date.from(Instant.now(clock)))
                .keyLocator(new StrictKeyLocator(keyRing))
                .build();
    }

    /**
     * Choisit la clé de vérification d'un token signé :
     * <ol>
     * <li>résolution de la clé via le {@code kid} de l'en-tête
     * ({@link SigningKeyRing#find(String)}) ;</li>
     * <li>refus si l'en-tête {@code alg} n'est pas exactement l'algorithme
     * configuré pour cette clé.</li>
     * </ol>
     * Les refus lèvent {@link UnsupportedJwtException}, converti en
     * {@link JwtValidationException} par {@link #parse(String)}.
     */
    private static final class StrictKeyLocator extends LocatorAdapter<Key> {

        private final SigningKeyRing keyRing;

        private StrictKeyLocator(SigningKeyRing keyRing) {
            this.keyRing = keyRing;
        }

        @Override
        protected Key locate(JwsHeader header) {
            String keyId = header.getKeyId();
            SigningKeyProvider provider = keyRing.find(keyId)
                    .orElseThrow(() -> new UnsupportedJwtException("Identifiant de clé (kid) inconnu : " + keyId));

            String expected = provider.algorithm().name();
            if (!expected.equals(header.getAlgorithm())) {
                throw new UnsupportedJwtException(
                        "Algorithme refusé : " + header.getAlgorithm() + " (attendu : " + expected + ").");
            }

            Key key = provider.verificationKey();
            if (key instanceof SecretKey || key instanceof PublicKey) {
                return key;
            }
            throw new IllegalStateException("Type de clé de vérification non supporté : " + key.getClass());
        }
    }

    /**
     * Convertit les {@code Claims} internes de jjwt vers le type public
     * {@link JwtClaims} de la librairie.
     */
    private JwtClaims toJwtClaims(Claims claims) {
        Map<String, Object> custom = new HashMap<>(claims);
        // Retire les claims standard déjà exposés via des accesseurs dédiés
        custom.remove(Claims.SUBJECT);
        custom.remove(Claims.ISSUED_AT);
        custom.remove(Claims.EXPIRATION);
        custom.remove(Claims.ID);
        custom.remove(Claims.ISSUER);
        custom.remove(Claims.AUDIENCE);
        custom.remove(Claims.NOT_BEFORE);

        return new JwtClaims(
                claims.getSubject(),
                claims.getId(),
                claims.getIssuedAt() != null ? claims.getIssuedAt().toInstant() : null,
                claims.getExpiration() != null ? claims.getExpiration().toInstant() : null,
                custom);
    }
}
