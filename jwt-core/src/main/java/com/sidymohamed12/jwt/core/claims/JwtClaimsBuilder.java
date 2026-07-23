package com.sidymohamed12.jwt.core.claims;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Builder fluide pour construire des claims personnalisés sans manipuler
 * directement une {@code Map<String, Object>}. Utilisé à la fois par
 * {@link com.sidymohamed12.jwt.core.token.JwtTokenSpec.Builder} (claims
 * explicites d'un token) et par {@link ClaimsCustomizer} (claims globaux
 * appliqués automatiquement à chaque génération).
 */
public final class JwtClaimsBuilder {

    private final Map<String, Object> claims = new LinkedHashMap<>();

    /**
     * Ajoute un claim ; ignoré silencieusement si {@code value} est {@code null}.
     */
    public JwtClaimsBuilder claim(String name, Object value) {
        if (value != null) {
            claims.put(name, value);
        }
        return this;
    }

    /**
     * Ajoute un claim UUID, sérialisé en chaîne de caractères ; ignoré si
     * {@code value} est {@code null}.
     */
    public JwtClaimsBuilder claim(String name, UUID value) {
        return claim(name, value == null ? null : value.toString());
    }

    /** @return une copie immuable des claims accumulés jusqu'ici. */
    public Map<String, Object> build() {
        return Map.copyOf(claims);
    }
}
