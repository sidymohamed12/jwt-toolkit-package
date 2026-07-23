package com.sidymohamed12.jwt.core.exception;

/** Levée spécifiquement quand un JWT, par ailleurs valide, est expiré. */
public class JwtExpiredException extends JwtValidationException {

    /**
     * @param message message d'erreur destiné aux logs/diagnostics
     * @param cause   exception d'origine (typiquement
     *                {@code io.jsonwebtoken.ExpiredJwtException})
     */
    public JwtExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
