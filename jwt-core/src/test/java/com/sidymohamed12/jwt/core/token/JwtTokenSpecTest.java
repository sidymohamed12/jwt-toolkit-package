package com.sidymohamed12.jwt.core.token;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenSpecTest {

    @Test
    void refuse_un_subject_manquant() {
        assertThatThrownBy(() -> JwtTokenSpec.builder().ttl(Duration.ofMinutes(5)).build())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void refuse_un_ttl_negatif_ou_nul() {
        assertThatThrownBy(() -> JwtTokenSpec.builder().subject("user").ttl(Duration.ZERO).build())
                .isInstanceOf(IllegalStateException.class);

        assertThatThrownBy(() -> JwtTokenSpec.builder().subject("user").ttl(Duration.ofSeconds(-1)).build())
                .isInstanceOf(IllegalStateException.class);
    }
}
