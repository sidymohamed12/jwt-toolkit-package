package com.sidymohamed12.jwt.core.token;

import com.sidymohamed12.jwt.core.claims.JwtClaims;
import com.sidymohamed12.jwt.core.exception.JwtGenerationException;
import com.sidymohamed12.jwt.core.exception.JwtValidationException;

/**
 * Service central de génération et validation de JWT.
 * <p>
 * Interface volontairement minimale (Interface Segregation Principle) :
 * la génération accepte un {@link JwtTokenSpec} unique pour permettre une
 * personnalisation totale des claims sans faire exploser la signature de
 * la méthode à chaque nouveau besoin métier (contrairement à des
 * paramètres positionnels comme {@code entrepotId}, {@code fournisseurId}...).
 */
public interface JwtTokenService {

    /**
     * Génère un JWT signé conforme à la spécification fournie.
     *
     * @throws JwtGenerationException si la signature échoue
     */
    String generate(JwtTokenSpec spec);

    /**
     * Parse et valide un JWT (signature, expiration, révocation).
     *
     * @throws JwtValidationException si le token est invalide, malformé,
     *                                expiré ou révoqué
     */
    JwtClaims parse(String token) throws JwtValidationException;

    /**
     * @return {@code true} si le token est valide (signature, expiration, non
     *         révoqué), {@code false} sinon.
     */
    boolean isValid(String token);

    /**
     * @return {@code true} si le token est expiré ou invalide, sans lever
     *         d'exception.
     */
    boolean isExpired(String token);
}
