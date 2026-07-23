package com.sidymohamed12.jwt.core.key;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RsaSigningKeyProviderTest {

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    @Test
    void construit_un_provider_complet_a_partir_de_cles_base64() throws Exception {
        KeyPair pair = generateKeyPair();
        String priv = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
        String pub = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());

        RsaSigningKeyProvider provider = RsaSigningKeyProvider.fromBase64(priv, pub, JwtAlgorithm.RS256);

        assertThat(provider.signingKey()).isEqualTo(pair.getPrivate());
        assertThat(provider.verificationKey()).isEqualTo(pair.getPublic());
    }

    @Test
    void mode_verification_seule_refuse_de_signer() throws Exception {
        KeyPair pair = generateKeyPair();
        RsaSigningKeyProvider provider = RsaSigningKeyProvider.verificationOnly(pair.getPublic(), JwtAlgorithm.RS256);

        assertThat(provider.verificationKey()).isEqualTo(pair.getPublic());
        assertThatThrownBy(provider::signingKey).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void refuse_un_algorithme_non_rsa() throws Exception {
        KeyPair pair = generateKeyPair();
        assertThatThrownBy(() -> new RsaSigningKeyProvider(pair.getPrivate(), pair.getPublic(), JwtAlgorithm.HS256))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refuse_des_cles_mal_encodees() {
        assertThatThrownBy(() -> RsaSigningKeyProvider.fromBase64("invalide", "invalide", JwtAlgorithm.RS256))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
