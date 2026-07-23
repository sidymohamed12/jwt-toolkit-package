package com.sidymohamed12.jwt.core.token;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;
import com.sidymohamed12.jwt.core.key.RsaSigningKeyProvider;
import com.sidymohamed12.jwt.core.revocation.NoOpTokenRevocationPort;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Scénario "microservices" : un service émetteur signe avec la clé privée,
 * un service consommateur, qui ne connaît que la clé publique, vérifie
 * sans jamais pouvoir signer lui-même.
 */
class RsaEndToEndTest {

    @Test
    void un_service_verificateur_valide_un_token_signe_par_le_service_emetteur() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        RsaSigningKeyProvider issuerProvider = new RsaSigningKeyProvider(
                pair.getPrivate(), pair.getPublic(), JwtAlgorithm.RS256);
        RsaSigningKeyProvider verifierProvider = RsaSigningKeyProvider.verificationOnly(
                pair.getPublic(), JwtAlgorithm.RS256);

        DefaultJwtTokenService issuerService = new DefaultJwtTokenService(
                issuerProvider, Clock.systemUTC(), List.of(), new NoOpTokenRevocationPort());
        DefaultJwtTokenService verifierService = new DefaultJwtTokenService(
                verifierProvider, Clock.systemUTC(), List.of(), new NoOpTokenRevocationPort());

        String token = issuerService.generate(JwtTokenSpec.builder()
                .subject("service-a")
                .ttl(Duration.ofMinutes(5))
                .claim("scope", "read:catalogue")
                .build());

        assertThat(verifierService.isValid(token)).isTrue();
        assertThat(verifierService.parse(token).getString("scope")).contains("read:catalogue");
    }
}
