package com.sidymohamed12.jwt.spring.security;

import com.sidymohamed12.jwt.core.claims.JwtClaims;

import org.springframework.security.core.Authentication;

/**
 * Point d'extension : convertit les claims d'un JWT déjà validé en un
 * {@link Authentication} Spring Security.
 * <p>
 * Chaque projet consommateur fournit sa propre implémentation (mapping
 * des rôles, chargement d'un principal métier, extraction de claims
 * personnalisés comme {@code entrepotId}...) — c'est ici que se joue la
 * "personnalisation des champs" côté sécurité. Le filtre
 * {@link JwtAuthenticationFilter} n'est activé par l'auto-configuration
 * que si un bean de ce type est présent.
 */
@FunctionalInterface
public interface JwtAuthenticationConverter {

    /**
     * @param claims claims d'un JWT déjà validé (signature + expiration vérifiées)
     * @return l'{@link Authentication} Spring Security correspondante, à placer
     *         dans le
     *         {@code SecurityContext}
     */
    Authentication convert(JwtClaims claims);
}
