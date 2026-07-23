package com.sidymohamed12.jwt.core.revocation;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Documente noir sur blanc le comportement par défaut de la librairie en
 * matière de révocation : {@link NoOpTokenRevocationPort} est un
 * no-op complet, jamais un frein à la validation d'un token. Ces tests ne
 * couvrent pas un "cas limite" — ils couvrent le comportement standard
 * que rencontrera tout projet consommateur n'ayant pas explicitement
 * branché son propre {@link TokenRevocationPort} (ex : Redis).
 */
class NoOpTokenRevocationPortTest {

    private final NoOpTokenRevocationPort port = new NoOpTokenRevocationPort();

    @Test
    void isRevoked_retourne_toujours_faux_meme_pour_un_token_inconnu_ou_invalide() {
        assertThat(port.isRevoked("nimporte-quel-token")).isFalse();
        assertThat(port.isRevoked("")).isFalse();
        assertThat(port.isRevoked(null)).isFalse();
    }

    @Test
    void revoke_nechoue_jamais_et_na_aucun_effet_observable() {
        // "no-op" signifie littéralement : aucune exception, aucun état modifié.
        assertThatCode(() -> port.revoke("un-token", Duration.ofMinutes(5))).doesNotThrowAnyException();
        assertThatCode(() -> port.revoke("un-token", Duration.ZERO)).doesNotThrowAnyException();
        assertThatCode(() -> port.revoke("un-token", Duration.ofDays(-1))).doesNotThrowAnyException();
        assertThatCode(() -> port.revoke(null, Duration.ofMinutes(5))).doesNotThrowAnyException();
    }

    @Test
    void appeler_revoke_ne_change_jamais_le_resultat_dun_isRevoked_ulterieur() {
        String token = "un-token-quelconque";

        assertThat(port.isRevoked(token)).isFalse();
        port.revoke(token, Duration.ofMinutes(15));
        // Toujours false après "révocation" : c'est le point central du no-op.
        assertThat(port.isRevoked(token)).isFalse();
    }
}
