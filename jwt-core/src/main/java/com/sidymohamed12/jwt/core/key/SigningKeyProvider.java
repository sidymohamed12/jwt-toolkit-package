package com.sidymohamed12.jwt.core.key;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;

import java.security.Key;

/**
 * Fournit les clés utilisées pour signer et vérifier un JWT.
 * <p>
 * Abstraction centrale (pattern Strategy) permettant de supporter aussi
 * bien un secret partagé (HMAC) qu'une paire de clés asymétrique
 * (RSA/EC) sans que le reste de la librairie n'ait à connaître le détail
 * cryptographique — {@link com.sidymohamed12.jwt.core.token.JwtTokenService}
 * ne dépend que de cette interface (Dependency Inversion Principle).
 * <p>
 * Implémentez cette interface pour brancher un provider personnalisé,
 * par exemple des clés récupérées depuis un HSM, AWS KMS ou HashiCorp
 * Vault plutôt que d'une configuration statique.
 */
public interface SigningKeyProvider {

    /** Algorithme associé aux clés fournies. */
    JwtAlgorithm algorithm();

    /**
     * Clé utilisée pour signer un nouveau token (HMAC : le secret partagé ;
     * RSA/EC : la clé privée). Peut lever {@link IllegalStateException} si
     * ce provider est configuré en mode "vérification seule".
     */
    Key signingKey();

    /**
     * Clé utilisée pour vérifier un token existant (HMAC : le même secret ;
     * RSA/EC : la clé publique).
     */
    Key verificationKey();
}
