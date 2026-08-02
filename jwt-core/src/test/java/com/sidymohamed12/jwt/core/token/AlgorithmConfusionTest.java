package com.sidymohamed12.jwt.core.token;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;
import com.sidymohamed12.jwt.core.exception.JwtValidationException;
import com.sidymohamed12.jwt.core.key.HmacSigningKeyProvider;
import com.sidymohamed12.jwt.core.key.RsaSigningKeyProvider;
import com.sidymohamed12.jwt.core.revocation.NoOpTokenRevocationPort;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Vérifie que la librairie ne confond jamais les familles d'algorithmes au
 * moment de la validation.
 * <p>
 * L'attaque "alg confusion" classique consiste à forger un token HS256 en
 * réutilisant la clé publique RSA d'un service comme secret HMAC (ou
 * inversement) — si le vérificateur ne distingue pas la famille d'algorithme
 * attendue, un attaquant qui connaît la clé publique (par définition
 * publique) peut alors signer des tokens arbitraires.
 * <p>
 * Ces tests forgent volontairement les tokens malveillants directement avec
 * jjwt (pas avec {@code jwt-core}), pour simuler un attaquant qui n'utilise
 * pas la librairie — seule la validation côté {@link DefaultJwtTokenService}
 * doit s'en protéger.
 */
class AlgorithmConfusionTest {

    @Test
    @DisplayName("un token HMAC forgé avec la clé publique RSA n'est jamais accepté par un service configuré en RSA")
    void token_hmac_refuse_par_service_rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        RsaSigningKeyProvider rsaProvider = RsaSigningKeyProvider.verificationOnly(
                pair.getPublic(), JwtAlgorithm.RS256);
        DefaultJwtTokenService rsaService = new DefaultJwtTokenService(
                rsaProvider, Clock.systemUTC(), List.of(), new NoOpTokenRevocationPort());

        // Attaque classique : la clé publique RSA est... publique. Un attaquant
        // peut donc l'utiliser comme "secret" HMAC pour forger un token HS256.
        SecretKey forgedSecret = Keys.hmacShaKeyFor(pair.getPublic().getEncoded());
        String forgedToken = Jwts.builder()
                .subject("attacker@example.com")
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(forgedSecret)
                .compact();

        assertThatThrownBy(() -> rsaService.parse(forgedToken))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    @DisplayName("un token RSA n'est jamais accepté par un service configuré en HMAC")
    void token_rsa_refuse_par_service_hmac() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        String secret = "0123456789abcdef0123456789abcdef0123456789abcdef";
        HmacSigningKeyProvider hmacProvider = new HmacSigningKeyProvider(secret, JwtAlgorithm.HS256);
        DefaultJwtTokenService hmacService = new DefaultJwtTokenService(
                hmacProvider, Clock.systemUTC(), List.of(), new NoOpTokenRevocationPort());

        String rsaToken = Jwts.builder()
                .subject("user@example.com")
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(pair.getPrivate())
                .compact();

        assertThatThrownBy(() -> hmacService.parse(rsaToken))
                .isInstanceOf(JwtValidationException.class);
    }
}
