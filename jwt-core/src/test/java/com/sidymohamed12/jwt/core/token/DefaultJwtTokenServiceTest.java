package com.sidymohamed12.jwt.core.token;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;
import com.sidymohamed12.jwt.core.claims.JwtClaims;
import com.sidymohamed12.jwt.core.exception.JwtExpiredException;
import com.sidymohamed12.jwt.core.exception.JwtValidationException;
import com.sidymohamed12.jwt.core.key.HmacSigningKeyProvider;
import com.sidymohamed12.jwt.core.revocation.NoOpTokenRevocationPort;
import com.sidymohamed12.jwt.core.revocation.TokenRevocationPort;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DefaultJwtTokenServiceTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef";

    private Instant now;
    private Clock clock;
    private DefaultJwtTokenService service;

    @BeforeEach
    void setUp() {
        now = Instant.parse("2026-07-23T10:00:00Z");
        clock = Clock.fixed(now, ZoneOffset.UTC);
        HmacSigningKeyProvider keyProvider = new HmacSigningKeyProvider(SECRET, JwtAlgorithm.HS256);
        service = new DefaultJwtTokenService(keyProvider, clock, List.of(), new NoOpTokenRevocationPort());
    }

    @Test
    void genere_puis_valide_un_token_avec_claims_personnalises() {
        UUID entrepotId = UUID.randomUUID();
        JwtTokenSpec spec = JwtTokenSpec.builder()
                .subject("user@example.com")
                .ttl(Duration.ofMinutes(15))
                .claim("entrepotId", entrepotId)
                .claim("roles", List.of("ADMIN", "GESTIONNAIRE"))
                .build();

        String token = service.generate(spec);
        JwtClaims claims = service.parse(token);

        assertThat(claims.subject()).isEqualTo("user@example.com");
        assertThat(claims.getUUID("entrepotId")).contains(entrepotId);
        assertThat(claims.getStringSet("roles")).containsExactlyInAnyOrder("ADMIN", "GESTIONNAIRE");
        assertThat(service.isValid(token)).isTrue();
    }

    @Test
    void rejette_un_token_expire() {
        JwtTokenSpec spec = JwtTokenSpec.builder()
                .subject("user@example.com")
                .ttl(Duration.ofSeconds(1))
                .build();
        String token = service.generate(spec);

        Clock later = Clock.fixed(now.plus(Duration.ofHours(1)), ZoneOffset.UTC);
        DefaultJwtTokenService serviceLater = new DefaultJwtTokenService(
                new HmacSigningKeyProvider(SECRET, JwtAlgorithm.HS256), later, List.of(),
                new NoOpTokenRevocationPort());

        assertThatThrownBy(() -> serviceLater.parse(token)).isInstanceOf(JwtExpiredException.class);
        assertThat(serviceLater.isExpired(token)).isTrue();
        assertThat(serviceLater.isValid(token)).isFalse();
    }

    @Test
    void rejette_un_token_signe_avec_un_autre_secret() {
        String autreSecret = "fedcba9876543210fedcba9876543210fedcba9876543210";
        DefaultJwtTokenService autreService = new DefaultJwtTokenService(
                new HmacSigningKeyProvider(autreSecret, JwtAlgorithm.HS256), clock, List.of(),
                new NoOpTokenRevocationPort());

        String token = autreService.generate(JwtTokenSpec.builder()
                .subject("user@example.com").ttl(Duration.ofMinutes(5)).build());

        assertThatThrownBy(() -> service.parse(token)).isInstanceOf(JwtValidationException.class);
    }

    @Test
    void applique_les_claims_customizers_globaux_sans_ecraser_les_claims_explicites() {
        DefaultJwtTokenService serviceAvecCustomizer = new DefaultJwtTokenService(
                new HmacSigningKeyProvider(SECRET, JwtAlgorithm.HS256), clock,
                List.of(builder -> builder.claim("issuerApp", "senpna").claim("env", "prod")),
                new NoOpTokenRevocationPort());

        String token = serviceAvecCustomizer.generate(JwtTokenSpec.builder()
                .subject("user@example.com")
                .ttl(Duration.ofMinutes(5))
                .claim("env", "override-explicite")
                .build());

        JwtClaims claims = serviceAvecCustomizer.parse(token);
        assertThat(claims.getString("issuerApp")).contains("senpna");
        assertThat(claims.getString("env")).contains("override-explicite");
    }

    @Test
    void refuse_un_token_deja_revoque() {
        TokenRevocationPort revocationPort = new TokenRevocationPort() {
            @Override
            public void revoke(String token, Duration ttl) {
                // non utilisé dans ce test
            }

            @Override
            public boolean isRevoked(String token) {
                return true;
            }
        };
        DefaultJwtTokenService serviceAvecRevocation = new DefaultJwtTokenService(
                new HmacSigningKeyProvider(SECRET, JwtAlgorithm.HS256), clock, List.of(), revocationPort);

        String token = serviceAvecRevocation.generate(JwtTokenSpec.builder()
                .subject("user@example.com").ttl(Duration.ofMinutes(5)).build());

        assertThatThrownBy(() -> serviceAvecRevocation.parse(token)).isInstanceOf(JwtValidationException.class);
    }
}
