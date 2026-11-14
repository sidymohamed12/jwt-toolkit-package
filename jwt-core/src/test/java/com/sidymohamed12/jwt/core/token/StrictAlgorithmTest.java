package com.sidymohamed12.jwt.core.token;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;
import com.sidymohamed12.jwt.core.exception.JwtValidationException;
import com.sidymohamed12.jwt.core.key.EcSigningKeyProvider;
import com.sidymohamed12.jwt.core.key.HmacSigningKeyProvider;
import com.sidymohamed12.jwt.core.key.RsaSigningKeyProvider;
import com.sidymohamed12.jwt.core.key.SigningKeyProvider;
import com.sidymohamed12.jwt.core.revocation.NoOpTokenRevocationPort;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * L'algorithme est imposé des deux côtés : à la signature (jamais déduit de la
 * taille de la clé) et à la validation (l'en-tête {@code alg} doit être
 * exactement l'algorithme configuré).
 */
class StrictAlgorithmTest {

    /** 48 octets = 384 bits : jjwt choisirait HS384 si l'algorithme n'était pas imposé. */
    private static final String SECRET_384_BITS = "0123456789abcdef0123456789abcdef0123456789abcdef";
    /** 64 octets = 512 bits : assez long pour HS256 comme pour HS512. */
    private static final String SECRET_512_BITS = SECRET_384_BITS + "0123456789abcdef";
    private static final String SUBJECT = "user@example.com";

    @Test
    @DisplayName("un secret de 384 bits configuré en HS256 signe bien en HS256 (pas HS384)")
    void signe_avec_l_algorithme_configure_et_non_deduit_de_la_cle() {
        DefaultJwtTokenService service = service(new HmacSigningKeyProvider(SECRET_384_BITS, JwtAlgorithm.HS256));

        String token = generate(service);

        assertThat(header(token)).contains("\"alg\":\"HS256\"");
        assertThat(service.isValid(token)).isTrue();
    }

    @Test
    @DisplayName("un token HS512 est refusé par un service HS256, même avec le bon secret")
    void refuse_un_autre_algorithme_hmac() {
        DefaultJwtTokenService issuer = service(new HmacSigningKeyProvider(SECRET_512_BITS, JwtAlgorithm.HS512));
        DefaultJwtTokenService verifier = service(new HmacSigningKeyProvider(SECRET_512_BITS, JwtAlgorithm.HS256));

        String token = generate(issuer);

        assertThat(header(token)).contains("\"alg\":\"HS512\"");
        assertThatThrownBy(() -> verifier.parse(token)).isInstanceOf(JwtValidationException.class);
        assertThat(verifier.isValid(token)).isFalse();
    }

    @Test
    @DisplayName("un token RS512 est refusé par un service RS256, même avec la bonne paire de clés")
    void refuse_un_autre_algorithme_rsa() throws Exception {
        KeyPair pair = rsaKeyPair();
        DefaultJwtTokenService issuer = service(
                new RsaSigningKeyProvider(pair.getPrivate(), pair.getPublic(), JwtAlgorithm.RS512));
        DefaultJwtTokenService verifier = service(
                RsaSigningKeyProvider.verificationOnly(pair.getPublic(), JwtAlgorithm.RS256));

        String token = generate(issuer);

        assertThatThrownBy(() -> verifier.parse(token)).isInstanceOf(JwtValidationException.class);
    }

    @Test
    @DisplayName("un token RS256 est accepté par un service RS256")
    void accepte_le_meme_algorithme_rsa() throws Exception {
        KeyPair pair = rsaKeyPair();
        DefaultJwtTokenService issuer = service(
                new RsaSigningKeyProvider(pair.getPrivate(), pair.getPublic(), JwtAlgorithm.RS256));
        DefaultJwtTokenService verifier = service(
                RsaSigningKeyProvider.verificationOnly(pair.getPublic(), JwtAlgorithm.RS256));

        String token = generate(issuer);

        assertThat(header(token)).contains("\"alg\":\"RS256\"");
        assertThat(verifier.parse(token).subject()).isEqualTo(SUBJECT);
    }

    @Test
    @DisplayName("ES256 : l'algorithme configuré est écrit dans l'en-tête et vérifié")
    void signe_et_verifie_en_es256() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        DefaultJwtTokenService issuer = service(
                new EcSigningKeyProvider(pair.getPrivate(), pair.getPublic(), JwtAlgorithm.ES256));
        DefaultJwtTokenService verifier = service(
                EcSigningKeyProvider.verificationOnly(pair.getPublic(), JwtAlgorithm.ES256));

        String token = generate(issuer);

        assertThat(header(token)).contains("\"alg\":\"ES256\"");
        assertThat(verifier.isValid(token)).isTrue();
    }

    private static DefaultJwtTokenService service(SigningKeyProvider provider) {
        return new DefaultJwtTokenService(provider, Clock.systemUTC(), List.of(), new NoOpTokenRevocationPort());
    }

    private static String generate(JwtTokenService service) {
        return service.generate(JwtTokenSpec.builder().subject(SUBJECT).ttl(Duration.ofMinutes(5)).build());
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    /** Décode l'en-tête JSON (première partie du token). */
    static String header(String token) {
        String encoded = token.substring(0, token.indexOf('.'));
        return new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8);
    }
}
