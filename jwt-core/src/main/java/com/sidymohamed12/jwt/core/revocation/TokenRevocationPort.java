package com.sidymohamed12.jwt.core.revocation;

import java.time.Duration;

/**
 * Abstraction (port au sens de la Clean Architecture) pour la révocation
 * de tokens, communément appelée "liste noire".
 * <p>
 * Un JWT est stateless par nature : une fois signé, il reste valide
 * jusqu'à son expiration, même après déconnexion ou changement de mot de
 * passe. Cette interface permet de brancher un mécanisme de révocation
 * (Redis, base de données, cache mémoire distribué...) sans coupler la
 * librairie à une technologie de stockage particulière — l'application
 * consommatrice fournit sa propre implémentation en fonction de son
 * infrastructure.
 */
public interface TokenRevocationPort {

    /**
     * Révoque un token pour la durée indiquée — généralement la durée de
     * vie résiduelle du token, afin que le stockage sous-jacent s'auto-nettoie
     * (TTL Redis, par exemple) sans purge manuelle.
     *
     * @param token le JWT complet (compact, signé) à révoquer
     * @param ttl   durée après laquelle l'entrée de révocation peut être purgée
     */
    void revoke(String token, Duration ttl);

    /**
     * @param token le JWT complet (compact, signé) à vérifier
     * @return {@code true} si le token a été révoqué.
     */
    boolean isRevoked(String token);
}
