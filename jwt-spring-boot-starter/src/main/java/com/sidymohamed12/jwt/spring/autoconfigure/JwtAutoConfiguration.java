package com.sidymohamed12.jwt.spring.autoconfigure;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;
import com.sidymohamed12.jwt.core.claims.ClaimsCustomizer;
import com.sidymohamed12.jwt.core.key.EcSigningKeyProvider;
import com.sidymohamed12.jwt.core.key.HmacSigningKeyProvider;
import com.sidymohamed12.jwt.core.key.RsaSigningKeyProvider;
import com.sidymohamed12.jwt.core.key.SigningKeyProvider;
import com.sidymohamed12.jwt.core.key.SigningKeyRing;
import com.sidymohamed12.jwt.core.revocation.NoOpTokenRevocationPort;
import com.sidymohamed12.jwt.core.revocation.TokenRevocationPort;
import com.sidymohamed12.jwt.core.token.DefaultJwtTokenService;
import com.sidymohamed12.jwt.core.token.JwtTokenService;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.time.Clock;
import java.util.List;

/**
 * Auto-configuration Spring Boot du service JWT.
 * <p>
 * Chaque bean est déclaré {@code @ConditionalOnMissingBean} : le projet
 * consommateur peut remplacer n'importe quelle pièce (provider de clé,
 * révocation, horloge...) en déclarant simplement son propre bean, sans
 * toucher à cette classe ni forker la librairie (principe Open/Closed).
 */
@AutoConfiguration
@EnableConfigurationProperties({ JwtProperties.class, JwtKeyRotationProperties.class })
public class JwtAutoConfiguration {

    private static final String REQUIRED_FOR = " est obligatoire pour l'algorithme ";
    private static final String PUBLIC_KEY = "public-key";

    /**
     * @return une horloge système UTC, sauf si l'application en fournit déjà une
     *         (utile pour les tests).
     */
    @Bean
    @ConditionalOnMissingBean
    public Clock jwtClock() {
        return Clock.systemUTC();
    }

    /**
     * @return {@link NoOpTokenRevocationPort} par défaut ; remplacé par tout bean
     *         {@link TokenRevocationPort} fourni par l'application (ex :
     *         implémentation Redis).
     */
    @Bean
    @ConditionalOnMissingBean
    public TokenRevocationPort tokenRevocationPort() {
        return new NoOpTokenRevocationPort();
    }

    /**
     * Construit le {@link SigningKeyProvider} adapté à {@code jwt.algorithm} :
     * {@link HmacSigningKeyProvider} pour la famille HMAC,
     * {@link RsaSigningKeyProvider}
     * ou {@link EcSigningKeyProvider} pour RSA/EC (lues depuis
     * {@code jwt.rsa.*}/{@code jwt.ec.*}).
     *
     * @throws IllegalStateException si les propriétés requises pour l'algorithme
     *                               choisi sont absentes
     */
    @Bean
    @ConditionalOnMissingBean
    public SigningKeyProvider signingKeyProvider(JwtProperties properties) {
        JwtAlgorithm algorithm = properties.algorithm();
        return switch (algorithm.family()) {
            case HMAC -> hmacProvider(properties.secret(), algorithm, "jwt.secret");
            case RSA -> {
                JwtProperties.Rsa rsa = properties.rsa() != null ? properties.rsa() : new JwtProperties.Rsa(null, null);
                requirePublicKey(rsa.publicKey(), algorithm, "jwt.rsa.");
                yield RsaSigningKeyProvider.fromBase64(rsa.privateKey(), rsa.publicKey(), algorithm);
            }
            case EC -> {
                JwtProperties.Ec ec = properties.ec() != null ? properties.ec() : new JwtProperties.Ec(null, null);
                requirePublicKey(ec.publicKey(), algorithm, "jwt.ec.");
                yield EcSigningKeyProvider.fromBase64(ec.privateKey(), ec.publicKey(), algorithm);
            }
        };
    }

    /**
     * Construit le trousseau de clés : la clé active est le
     * {@link SigningKeyProvider} (identifiée par {@code jwt.rotation.active-key-id}
     * si renseigné), complétée des clés précédentes
     * {@code jwt.rotation.previous-keys}, en vérification seule.
     *
     * @throws IllegalStateException    si une clé précédente est incomplète, ou si
     *                                  des clés précédentes sont déclarées sans
     *                                  {@code active-key-id}
     * @throws IllegalArgumentException si un {@code kid} est vide ou dupliqué
     */
    @Bean
    @ConditionalOnMissingBean
    public SigningKeyRing signingKeyRing(SigningKeyProvider signingKeyProvider, JwtProperties properties,
            JwtKeyRotationProperties rotation) {
        SigningKeyRing.Builder builder = SigningKeyRing.builder();
        String activeKeyId = rotation.activeKeyId();
        if (activeKeyId == null || activeKeyId.isBlank()) {
            builder.active(signingKeyProvider);
        } else {
            builder.active(activeKeyId, signingKeyProvider);
        }
        for (JwtKeyRotationProperties.PreviousKey previous : rotation.previousKeys()) {
            JwtAlgorithm algorithm = previous.algorithm() != null ? previous.algorithm() : properties.algorithm();
            builder.previous(previous.keyId(), verificationProvider(previous, algorithm));
        }
        return builder.build();
    }

    /** Construit une clé précédente, en vérification seule. */
    private static SigningKeyProvider verificationProvider(JwtKeyRotationProperties.PreviousKey previous,
            JwtAlgorithm algorithm) {
        String prefix = "jwt.rotation.previous-keys[" + previous.keyId() + "].";
        return switch (algorithm.family()) {
            case HMAC -> hmacProvider(previous.secret(), algorithm, prefix + "secret");
            case RSA -> {
                requirePublicKey(previous.publicKey(), algorithm, prefix);
                yield RsaSigningKeyProvider.fromBase64(null, previous.publicKey(), algorithm);
            }
            case EC -> {
                requirePublicKey(previous.publicKey(), algorithm, prefix);
                yield EcSigningKeyProvider.fromBase64(null, previous.publicKey(), algorithm);
            }
        };
    }

    private static HmacSigningKeyProvider hmacProvider(String secret, JwtAlgorithm algorithm, String property) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException(property + REQUIRED_FOR + algorithm);
        }
        return new HmacSigningKeyProvider(secret, algorithm);
    }

    private static void requirePublicKey(String publicKey, JwtAlgorithm algorithm, String prefix) {
        if (publicKey == null || publicKey.isBlank()) {
            throw new IllegalStateException(prefix + PUBLIC_KEY + REQUIRED_FOR + algorithm);
        }
    }

    /**
     * Assemble le {@link JwtTokenService} final à partir des autres beans, en
     * collectant
     * tous les beans {@link ClaimsCustomizer} déclarés par l'application (ordonnés
     * via
     * {@link org.springframework.core.annotation.Order} si besoin).
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtTokenService jwtTokenService(SigningKeyRing signingKeyRing, Clock jwtClock,
            ObjectProvider<ClaimsCustomizer> claimsCustomizers, TokenRevocationPort tokenRevocationPort) {
        List<ClaimsCustomizer> customizers = claimsCustomizers.orderedStream().toList();
        return new DefaultJwtTokenService(signingKeyRing, jwtClock, customizers, tokenRevocationPort);
    }
}
