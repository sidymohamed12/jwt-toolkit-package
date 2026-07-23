package com.sidymohamed12.jwt.core.exception;

/**
 * Levée quand la génération d'un JWT échoue (clé invalide, erreur de
 * signature...).
 */
public class JwtGenerationException extends RuntimeException {

    /**
     * @param message message d'erreur destiné aux logs/diagnostics
     * @param cause   exception d'origine ayant fait échouer la signature du token
     */
    public JwtGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}
