package com.sidymohamed12.jwt.core.token;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;
import com.sidymohamed12.jwt.core.exception.JwtValidationException;
import com.sidymohamed12.jwt.core.key.HmacSigningKeyProvider;
import com.sidymohamed12.jwt.core.key.SigningKeyRing;
import com.sidymohamed12.jwt.core.revocation.NoOpTokenRevocationPort;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Rotation des clés : après le passage de la clé "2026-10" à la clé "2026-11",
 * les tokens déjà émis restent valides jusqu'à leur expiration, les nouveaux
 * sont signés avec la nouvelle clé, et un {@code kid} inconnu est refusé.
 */
class KeyRotationTest {

    private static final String KID_OCTOBER = "2026-10";
    private static final String KID_NOVEMBER = "2026-11";
    private static final String OLD_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef";
    private static final String NEW_SECRET = "fedcba9876543210fedcba9876543210fedcba9876543210";
    private static final String OTHER_SECRET = "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8";
    private static final String SUBJECT = "user@example.com";

    /** Service après rotation : nouvelle clé active, ancienne en vérification seule. */
    private final DefaultJwtTokenService rotatedService = service(SigningKeyRing.builder()
            .active(KID_NOVEMBER, hmac(NEW_SECRET))
            .previous(KID_OCTOBER, hmac(OLD_SECRET))
            .build());

    @Test
    @DisplayName("un token émis avec l'ancienne clé reste valide après la rotation")
    void accepte_un_token_signe_par_la_cle_precedente() {
        DefaultJwtTokenService beforeRotation = service(SigningKeyRing.builder()
                .active(KID_OCTOBER, hmac(OLD_SECRET)).build());

        String oldToken = generate(beforeRotation);

        assertThat(StrictAlgorithmTest.header(oldToken)).contains("\"kid\":\"" + KID_OCTOBER + "\"");
        assertThat(rotatedService.parse(oldToken).subject()).isEqualTo(SUBJECT);
    }

    @Test
    @DisplayName("les nouveaux tokens portent le kid de la clé active")
    void signe_avec_la_cle_active_et_ecrit_son_kid() {
        String token = generate(rotatedService);

        assertThat(StrictAlgorithmTest.header(token)).contains("\"kid\":\"" + KID_NOVEMBER + "\"");
        assertThat(rotatedService.isValid(token)).isTrue();

        // signé avec la nouvelle clé : un service qui ne connaît que l'ancienne le refuse
        DefaultJwtTokenService oldOnly = service(SigningKeyRing.builder()
                .active(KID_OCTOBER, hmac(OLD_SECRET)).build());
        assertThat(oldOnly.isValid(token)).isFalse();
    }

    @Test
    @DisplayName("un kid inconnu est refusé")
    void refuse_un_kid_inconnu() {
        DefaultJwtTokenService unknownIssuer = service(SigningKeyRing.builder()
                .active("2026-09", hmac(OTHER_SECRET)).build());

        String token = generate(unknownIssuer);

        assertThatThrownBy(() -> rotatedService.parse(token)).isInstanceOf(JwtValidationException.class);
        assertThat(rotatedService.isExpired(token)).isTrue();
    }

    @Test
    @DisplayName("un kid connu mais signé avec une autre clé est refusé (signature invalide)")
    void refuse_un_kid_connu_avec_une_mauvaise_signature() {
        DefaultJwtTokenService forger = service(SigningKeyRing.builder()
                .active(KID_OCTOBER, hmac(OTHER_SECRET)).build());

        String forged = generate(forger);

        assertThatThrownBy(() -> rotatedService.parse(forged)).isInstanceOf(JwtValidationException.class);
    }

    @Test
    @DisplayName("un token sans kid est vérifié avec la clé active")
    void verifie_un_token_sans_kid_avec_la_cle_active() {
        DefaultJwtTokenService withoutKid = service(SigningKeyRing.of(hmac(NEW_SECRET)));
        DefaultJwtTokenService oldWithoutKid = service(SigningKeyRing.of(hmac(OLD_SECRET)));

        String tokenNewKey = generate(withoutKid);
        String tokenOldKey = generate(oldWithoutKid);

        assertThat(StrictAlgorithmTest.header(tokenNewKey)).doesNotContain("kid");
        assertThat(rotatedService.isValid(tokenNewKey)).isTrue();
        // sans kid, impossible de savoir qu'il s'agit de l'ancienne clé : refusé
        assertThat(rotatedService.isValid(tokenOldKey)).isFalse();
    }

    private static HmacSigningKeyProvider hmac(String secret) {
        return new HmacSigningKeyProvider(secret, JwtAlgorithm.HS256);
    }

    private static DefaultJwtTokenService service(SigningKeyRing ring) {
        return new DefaultJwtTokenService(ring, Clock.systemUTC(), List.of(), new NoOpTokenRevocationPort());
    }

    private static String generate(JwtTokenService service) {
        return service.generate(JwtTokenSpec.builder().subject(SUBJECT).ttl(Duration.ofMinutes(5)).build());
    }
}
