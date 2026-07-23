package com.sidymohamed12.jwt.core.key;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EcSigningKeyProviderTest {

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    @Test
    void construit_un_provider_complet_a_partir_de_cles_base64() throws Exception {
        KeyPair pair = generateKeyPair();
        String priv = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
        String pub = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());

        EcSigningKeyProvider provider = EcSigningKeyProvider.fromBase64(priv, pub, JwtAlgorithm.ES256);

        assertThat(provider.signingKey()).isEqualTo(pair.getPrivate());
        assertThat(provider.verificationKey()).isEqualTo(pair.getPublic());
    }

    @Test
    void mode_verification_seule_refuse_de_signer() throws Exception {
        KeyPair pair = generateKeyPair();
        EcSigningKeyProvider provider = EcSigningKeyProvider.verificationOnly(pair.getPublic(), JwtAlgorithm.ES256);

        assertThatThrownBy(provider::signingKey).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void refuse_un_algorithme_non_ec() throws Exception {
        KeyPair pair = generateKeyPair();
        assertThatThrownBy(() -> new EcSigningKeyProvider(pair.getPrivate(), pair.getPublic(), JwtAlgorithm.RS256))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
