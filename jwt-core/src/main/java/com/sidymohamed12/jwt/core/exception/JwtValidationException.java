package com.sidymohamed12.jwt.core.exception;

/**
 * Exception racine levée lors de l'échec de validation d'un JWT
 * (signature invalide, format malformé, expiration, révocation...).
 * <p>
 * La librairie ne laisse jamais fuiter les exceptions de <em>jjwt</em>
 * vers l'appelant : elles sont systématiquement traduites vers cette
 * hiérarchie, afin que le code consommateur ne dépende que de
 * {@code jwt-core} (anti-corruption layer).
 */
public class JwtValidationException extends RuntimeException {

    /** @param message message d'erreur destiné aux logs/diagnostics. */
    public JwtValidationException(String message) {
        super(message);
    }

    /**
     * @param message message d'erreur destiné aux logs/diagnostics
     * @param cause   exception d'origine (typiquement une exception jjwt, masquée à
     *                l'appelant)
     */
    public JwtValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
