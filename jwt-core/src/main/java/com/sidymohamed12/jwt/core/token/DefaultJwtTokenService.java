package com.sidymohamed12.jwt.core.token;

import com.sidymohamed12.jwt.core.claims.ClaimsCustomizer;
import com.sidymohamed12.jwt.core.claims.JwtClaims;
import com.sidymohamed12.jwt.core.claims.JwtClaimsBuilder;
import com.sidymohamed12.jwt.core.exception.JwtExpiredException;
import com.sidymohamed12.jwt.core.exception.JwtGenerationException;
import com.sidymohamed12.jwt.core.exception.JwtValidationException;
import com.sidymohamed12.jwt.core.key.SigningKeyProvider;
import com.sidymohamed12.jwt.core.revocation.TokenRevocationPort;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Implémentation par défaut de {@link JwtTokenService}, basée sur
 * <a href="https://github.com/jwtk/jjwt">jjwt</a>.
 * <p>
 * jjwt reste un détail d'implémentation confiné à ce package : les types
 * exposés à l'appelant ({@link JwtClaims}, {@link JwtValidationException})
 * sont ceux de la librairie, jamais ceux de jjwt (Dependency Inversion /
 * anti-corruption layer). Remplacer jjwt par une autre implémentation JWT
 * à l'avenir n'impacterait donc aucun code consommateur.
 */
public final class DefaultJwtTokenService implements JwtTokenService {

    private final SigningKeyProvider signingKeyProvider;
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
        this.signingKeyProvider = signingKeyProvider;
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

            return jwtBuilder.signWith(signingKeyProvider.signingKey()).compact();
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
            Claims claims = parserBuilder().build().parseSignedClaims(token).getPayload();
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
            parserBuilder().build().parseSignedClaims(token);
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
     * Construit un parseur jjwt configuré avec l'horloge et la bonne clé de
     * vérification
     * (secret HMAC ou clé publique RSA/EC, selon le type retourné par le
     * {@link SigningKeyProvider}).
     *
     * @throws IllegalStateException si le type de clé retourné par le provider
     *                               n'est ni
     *                               {@link SecretKey} ni {@link PublicKey}
     */
    private JwtParserBuilder parserBuilder() {
        JwtParserBuilder builder = Jwts.parser().clock(() -> Date.from(Instant.now(clock)));
        Key key = signingKeyProvider.verificationKey();
        if (key instanceof SecretKey secretKey) {
            builder.verifyWith(secretKey);
        } else if (key instanceof PublicKey publicKey) {
            builder.verifyWith(publicKey);
        } else {
            throw new IllegalStateException("Type de clé de vérification non supporté : " + key.getClass());
        }
        return builder;
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
