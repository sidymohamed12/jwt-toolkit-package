package com.sidymohamed12.jwt.core.claims;

/**
 * Point d'extension permettant d'ajouter automatiquement des claims à
 * <strong>chaque</strong> token généré (ex : {@code issuer}, {@code env},
 * version d'API...), sans modifier le code appelant ni la librairie
 * (principe Open/Closed).
 * <p>
 * Enregistrez une ou plusieurs implémentations — côté Spring, un simple
 * bean suffit, l'auto-configuration les injecte automatiquement dans
 * {@code JwtTokenService}. Les claims explicites d'un
 * {@link com.sidymohamed12.jwt.core.token.JwtTokenSpec} restent
 * prioritaires en cas de collision de nom.
 */
@FunctionalInterface
public interface ClaimsCustomizer {

    /** @param builder builder à enrichir avec les claims globaux à ajouter. */
    void customize(JwtClaimsBuilder builder);
}
