package com.sidymohamed12.jwt.spring.autoconfigure;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;
import com.sidymohamed12.jwt.core.key.HmacSigningKeyProvider;
import com.sidymohamed12.jwt.core.key.SigningKeyRing;
import com.sidymohamed12.jwt.core.revocation.NoOpTokenRevocationPort;
import com.sidymohamed12.jwt.core.token.DefaultJwtTokenService;
import com.sidymohamed12.jwt.core.token.JwtTokenService;
import com.sidymohamed12.jwt.core.token.JwtTokenSpec;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwtKeyRotationAutoConfigurationTest {

    private static final String NEW_SECRET = "fedcba9876543210fedcba9876543210fedcba9876543210";
    private static final String OLD_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef";
    private static final String KID_NOVEMBER = "2026-11";
    private static final String KID_OCTOBER = "2026-10";

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class))
            .withPropertyValues("jwt.secret=" + NEW_SECRET);

    @Test
    void sans_rotation_le_trousseau_contient_une_seule_cle_sans_kid() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(SigningKeyRing.class);
            assertThat(context.getBean(SigningKeyRing.class).activeKeyId()).isEmpty();
        });
    }

    @Test
    void accepte_les_tokens_de_la_cle_precedente_configuree() {
        contextRunner
                .withPropertyValues(
                        "jwt.rotation.active-key-id=" + KID_NOVEMBER,
                        "jwt.rotation.previous-keys[0].key-id=" + KID_OCTOBER,
                        "jwt.rotation.previous-keys[0].secret=" + OLD_SECRET)
                .run(context -> {
                    SigningKeyRing ring = context.getBean(SigningKeyRing.class);
                    assertThat(ring.activeKeyId()).contains(KID_NOVEMBER);
                    assertThat(ring.find(KID_OCTOBER)).isPresent();

                    String oldToken = new DefaultJwtTokenService(
                            SigningKeyRing.builder()
                                    .active(KID_OCTOBER, new HmacSigningKeyProvider(OLD_SECRET, JwtAlgorithm.HS256))
                                    .build(),
                            Clock.systemUTC(), List.of(), new NoOpTokenRevocationPort())
                            .generate(JwtTokenSpec.builder().subject("user").ttl(Duration.ofMinutes(5)).build());

                    assertThat(context.getBean(JwtTokenService.class).isValid(oldToken)).isTrue();
                });
    }

    @Test
    void echoue_si_une_cle_precedente_na_pas_de_secret() {
        contextRunner
                .withPropertyValues(
                        "jwt.rotation.active-key-id=" + KID_NOVEMBER,
                        "jwt.rotation.previous-keys[0].key-id=" + KID_OCTOBER)
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void echoue_si_des_cles_precedentes_sont_declarees_sans_active_key_id() {
        contextRunner
                .withPropertyValues(
                        "jwt.rotation.previous-keys[0].key-id=" + KID_OCTOBER,
                        "jwt.rotation.previous-keys[0].secret=" + OLD_SECRET)
                .run(context -> assertThat(context).hasFailed());
    }
}
