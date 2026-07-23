package com.sidymohamed12.jwt.spring.autoconfigure;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * Propriétés de configuration exposées sous le préfixe {@code jwt.*}.
 *
 * <pre>{@code
 * jwt:
 *   algorithm: HS256           # HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512
 *   secret: ${JWT_SECRET}      # requis pour un algorithme HMAC
 *   access-token-ttl: PT15M
 *   refresh-token-ttl: P7D
 *   rsa:
 *     public-key: ${JWT_RSA_PUBLIC_KEY}
 *     private-key: ${JWT_RSA_PRIVATE_KEY}   # omis côté service "vérification seule"
 * }</pre>
 */
@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
        /** Algorithme de signature ; {@code HS256} par défaut. */
        @DefaultValue("HS256") JwtAlgorithm algorithm,
        /** Secret partagé, requis uniquement pour un algorithme de la famille HMAC. */
        String secret,
        /**
         * Clés RSA (jwt.rsa.*), requises uniquement pour un algorithme de la famille
         * RSA.
         */
        Rsa rsa,
        /**
         * Clés EC (jwt.ec.*), requises uniquement pour un algorithme de la famille EC.
         */
        Ec ec,
        /** Durée de vie des tokens d'accès ; {@code PT15M} (15 minutes) par défaut. */
        @DefaultValue("PT15M") Duration accessTokenTtl,
        /**
         * Durée de vie des tokens de rafraîchissement ; {@code P7D} (7 jours) par
         * défaut.
         */
        @DefaultValue("P7D") Duration refreshTokenTtl) {

    /** Clés RSA encodées en Base64 (PKCS8/X509, avec ou sans en-têtes PEM). */
    public record Rsa(String privateKey, String publicKey) {
    }

    /** Clés EC encodées en Base64 (PKCS8/X509, avec ou sans en-têtes PEM). */
    public record Ec(String privateKey, String publicKey) {
    }
}
