package com.sidymohamed12.jwt.core.key;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HmacSigningKeyProviderTest {

    @Test
    void refuse_un_secret_trop_court() {
        assertThatThrownBy(() -> new HmacSigningKeyProvider("trop-court", JwtAlgorithm.HS256))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("256");
    }

    @Test
    void accepte_un_secret_de_taille_suffisante() {
        String secret = "0123456789abcdef0123456789abcdef"; // 33 caractères -> 264 bits
        HmacSigningKeyProvider provider = new HmacSigningKeyProvider(secret, JwtAlgorithm.HS256);

        assertThat(provider.algorithm()).isEqualTo(JwtAlgorithm.HS256);
        assertThat(provider.signingKey()).isEqualTo(provider.verificationKey());
    }

    @Test
    void refuse_un_algorithme_non_hmac() {
        String secret = "0123456789abcdef0123456789abcdef";
        assertThatThrownBy(() -> new HmacSigningKeyProvider(secret, JwtAlgorithm.RS256))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
