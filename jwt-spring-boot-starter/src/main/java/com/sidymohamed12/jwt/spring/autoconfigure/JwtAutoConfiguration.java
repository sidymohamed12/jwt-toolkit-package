package com.sidymohamed12.jwt.spring.autoconfigure;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;
import com.sidymohamed12.jwt.core.claims.ClaimsCustomizer;
import com.sidymohamed12.jwt.core.key.EcSigningKeyProvider;
import com.sidymohamed12.jwt.core.key.HmacSigningKeyProvider;
import com.sidymohamed12.jwt.core.key.RsaSigningKeyProvider;
import com.sidymohamed12.jwt.core.key.SigningKeyProvider;
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
@EnableConfigurationProperties(JwtProperties.class)
public class JwtAutoConfiguration {

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
            case HMAC -> {
                if (properties.secret() == null || properties.secret().isBlank()) {
                    throw new IllegalStateException(
                            "jwt.secret est obligatoire pour l'algorithme " + algorithm);
                }
                yield new HmacSigningKeyProvider(properties.secret(), algorithm);
            }
            case RSA -> {
                if (properties.rsa() == null || properties.rsa().publicKey() == null) {
                    throw new IllegalStateException(
                            "jwt.rsa.public-key est obligatoire pour l'algorithme " + algorithm
                                    + " (jwt.rsa.private-key en plus côté service émetteur)");
                }
                yield RsaSigningKeyProvider.fromBase64(
                        properties.rsa().privateKey(), properties.rsa().publicKey(), algorithm);
            }
            case EC -> {
                if (properties.ec() == null || properties.ec().publicKey() == null) {
                    throw new IllegalStateException(
                            "jwt.ec.public-key est obligatoire pour l'algorithme " + algorithm
                                    + " (jwt.ec.private-key en plus côté service émetteur)");
                }
                yield EcSigningKeyProvider.fromBase64(
                        properties.ec().privateKey(), properties.ec().publicKey(), algorithm);
            }
        };
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
    public JwtTokenService jwtTokenService(SigningKeyProvider signingKeyProvider, Clock jwtClock,
            ObjectProvider<ClaimsCustomizer> claimsCustomizers, TokenRevocationPort tokenRevocationPort) {
        List<ClaimsCustomizer> customizers = claimsCustomizers.orderedStream().toList();
        return new DefaultJwtTokenService(signingKeyProvider, jwtClock, customizers, tokenRevocationPort);
    }
}
