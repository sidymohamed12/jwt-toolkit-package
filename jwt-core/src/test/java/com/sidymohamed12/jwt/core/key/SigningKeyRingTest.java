package com.sidymohamed12.jwt.core.key;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SigningKeyRingTest {

    private static final String KID_ACTIVE = "2026-11";
    private static final String KID_PREVIOUS = "2026-10";

    private final SigningKeyProvider activeKey = new HmacSigningKeyProvider(
            "0123456789abcdef0123456789abcdef0123456789abcdef", JwtAlgorithm.HS256);
    private final SigningKeyProvider previousKey = new HmacSigningKeyProvider(
            "fedcba9876543210fedcba9876543210fedcba9876543210", JwtAlgorithm.HS256);

    @Test
    void mode_cle_unique_resout_toujours_la_cle_active() {
        SigningKeyRing ring = SigningKeyRing.of(activeKey);

        assertThat(ring.activeKeyId()).isEmpty();
        assertThat(ring.active()).isSameAs(activeKey);
        assertThat(ring.find(null)).containsSame(activeKey);
        assertThat(ring.find("nimporte-quel-kid")).containsSame(activeKey);
    }

    @Test
    void resout_la_cle_active_et_les_cles_precedentes_par_kid() {
        SigningKeyRing ring = SigningKeyRing.builder()
                .active(KID_ACTIVE, activeKey)
                .previous(KID_PREVIOUS, previousKey)
                .build();

        assertThat(ring.activeKeyId()).contains(KID_ACTIVE);
        assertThat(ring.find(KID_ACTIVE)).containsSame(activeKey);
        assertThat(ring.find(KID_PREVIOUS)).containsSame(previousKey);
        assertThat(ring.find(null)).containsSame(activeKey);
    }

    @Test
    void un_kid_inconnu_ne_resout_aucune_cle() {
        SigningKeyRing ring = SigningKeyRing.builder().active(KID_ACTIVE, activeKey).build();

        assertThat(ring.find("2026-09")).isEmpty();
    }

    @Test
    void refuse_un_kid_duplique() {
        SigningKeyRing.Builder builder = SigningKeyRing.builder()
                .active(KID_ACTIVE, activeKey)
                .previous(KID_PREVIOUS, previousKey);

        assertThatThrownBy(() -> builder.previous(KID_PREVIOUS, previousKey))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refuse_un_kid_actif_aussi_declare_comme_cle_precedente() {
        SigningKeyRing.Builder builder = SigningKeyRing.builder()
                .active(KID_ACTIVE, activeKey)
                .previous(KID_ACTIVE, previousKey);

        assertThatThrownBy(builder::build).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refuse_des_cles_precedentes_si_la_cle_active_na_pas_de_kid() {
        SigningKeyRing.Builder builder = SigningKeyRing.builder()
                .active(activeKey)
                .previous(KID_PREVIOUS, previousKey);

        assertThatThrownBy(builder::build).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void refuse_un_trousseau_sans_cle_active() {
        SigningKeyRing.Builder builder = SigningKeyRing.builder();

        assertThatThrownBy(builder::build).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void refuse_un_kid_vide() {
        SigningKeyRing.Builder builder = SigningKeyRing.builder();

        assertThatThrownBy(() -> builder.active(" ", activeKey)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> builder.previous(null, previousKey)).isInstanceOf(IllegalArgumentException.class);
    }
}
