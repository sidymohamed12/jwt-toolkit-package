package com.sidymohamed12.jwt.core.algorithm;

/**
 * Algorithmes de signature supportés par la librairie.
 * <p>
 * Chaque valeur regroupe la famille cryptographique (HMAC symétrique,
 * RSA ou EC asymétrique) et la taille minimale de clé recommandée, afin
 * de fournir un garde-fou au moment de la configuration : un secret ou
 * une clé trop courte est rejeté tôt, avec un message explicite, plutôt
 * que de produire un token faible en silence.
 */
public enum JwtAlgorithm {

    /** HMAC-SHA256 — secret d'au moins 256 bits (32 caractères ASCII). */
    HS256(Family.HMAC, 256),
    /** HMAC-SHA384 — secret d'au moins 384 bits (48 caractères ASCII). */
    HS384(Family.HMAC, 384),
    /** HMAC-SHA512 — secret d'au moins 512 bits (64 caractères ASCII). */
    HS512(Family.HMAC, 512),

    /** RSASSA-PKCS1-v1_5 avec SHA-256 — clé RSA d'au moins 2048 bits. */
    RS256(Family.RSA, 2048),
    /** RSASSA-PKCS1-v1_5 avec SHA-384 — clé RSA d'au moins 2048 bits. */
    RS384(Family.RSA, 2048),
    /** RSASSA-PKCS1-v1_5 avec SHA-512 — clé RSA d'au moins 2048 bits. */
    RS512(Family.RSA, 2048),

    /** ECDSA sur la courbe P-256 (secp256r1) avec SHA-256. */
    ES256(Family.EC, 256),
    /** ECDSA sur la courbe P-384 (secp384r1) avec SHA-384. */
    ES384(Family.EC, 384),
    /** ECDSA sur la courbe P-521 (secp521r1) avec SHA-512. */
    ES512(Family.EC, 521);

    /**
     * Famille cryptographique : détermine le type de {@code SigningKeyProvider} à
     * utiliser.
     */
    public enum Family {
        /** Secret partagé (symétrique) : la même clé signe et vérifie. */
        HMAC,
        /**
         * Paire de clés RSA (asymétrique) : clé privée pour signer, clé publique pour
         * vérifier.
         */
        RSA,
        /**
         * Paire de clés à courbe elliptique (asymétrique), plus compacte que RSA à
         * sécurité équivalente.
         */
        EC
    }

    private final Family family;
    private final int minKeyBits;

    /**
     * @param family     famille cryptographique de l'algorithme
     * @param minKeyBits taille minimale (en bits) de clé/secret recommandée pour
     *                   cet algorithme
     */
    JwtAlgorithm(Family family, int minKeyBits) {
        this.family = family;
        this.minKeyBits = minKeyBits;
    }

    /** @return la famille cryptographique (HMAC, RSA ou EC) de cet algorithme. */
    public Family family() {
        return family;
    }

    /** Taille minimale (en bits) recommandée pour la clé/le secret associé. */
    public int minKeyBits() {
        return minKeyBits;
    }

    /**
     * @return {@code true} si cet algorithme est de la famille HMAC (secret
     *         partagé).
     */
    public boolean isHmac() {
        return family == Family.HMAC;
    }

    /**
     * @return {@code true} si cet algorithme est asymétrique (RSA ou EC, paire clé
     *         privée/publique).
     */
    public boolean isAsymmetric() {
        return family != Family.HMAC;
    }
}
