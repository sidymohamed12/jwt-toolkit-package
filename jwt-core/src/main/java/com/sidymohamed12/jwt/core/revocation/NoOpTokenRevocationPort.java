package com.sidymohamed12.jwt.core.revocation;

import java.time.Duration;

/**
 * Implémentation par défaut, sans effet : aucune révocation n'est
 * réellement active. Utilisée quand le projet consommateur ne fournit
 * pas de mécanisme de révocation (Redis ou autre) — le service JWT reste
 * pleinement fonctionnel (génération/validation), simplement sans liste
 * noire. À remplacer explicitement (bean Spring ou instanciation
 * manuelle) dès que la révocation immédiate est un besoin de sécurité du
 * projet.
 */
public final class NoOpTokenRevocationPort implements TokenRevocationPort {

    @Override
    public void revoke(String token, Duration ttl) {
        // no-op : comportement assumé et documenté
    }

    @Override
    public boolean isRevoked(String token) {
        return false;
    }
}
