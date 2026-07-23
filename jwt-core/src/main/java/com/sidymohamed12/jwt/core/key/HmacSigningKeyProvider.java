package com.sidymohamed12.jwt.core.key;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;

import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * {@link SigningKeyProvider} basé sur un secret partagé (HMAC).
 * <p>
 * Adapté quand un seul service (ou un groupe de confiance partageant le
 * même secret, par exemple via un vault central) émet et valide les
 * tokens. Pour un scénario où plusieurs services ne doivent que
 * <em>vérifier</em> sans jamais pouvoir signer, préférez
 * {@link RsaSigningKeyProvider} ou {@link EcSigningKeyProvider}.
 */
public final class HmacSigningKeyProvider implements SigningKeyProvider {

    private final JwtAlgorithm algorithm;
    private final SecretKey secretKey;

    /**
     * @param secret    secret partagé en UTF-8 ; sa longueur en bits doit être
     *                  supérieure ou égale à {@link JwtAlgorithm#minKeyBits()}
     * @param algorithm algorithme HMAC à utiliser (HS256, HS384 ou HS512)
     * @throws NullPointerException     si {@code secret} ou {@code algorithm} est
     *                                  {@code null}
     * @throws IllegalArgumentException si {@code algorithm} n'est pas de la famille
     *                                  HMAC,
     *                                  ou si {@code secret} est trop court pour
     *                                  l'algorithme demandé
     */
    public HmacSigningKeyProvider(String secret, JwtAlgorithm algorithm) {
        Objects.requireNonNull(secret, "secret ne peut pas être null");
        Objects.requireNonNull(algorithm, "algorithm ne peut pas être null");
        if (algorithm.family() != JwtAlgorithm.Family.HMAC) {
            throw new IllegalArgumentException(
                    "HmacSigningKeyProvider ne supporte que les algorithmes HMAC, reçu : " + algorithm);
        }

        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        int secretBits = secretBytes.length * 8;
        if (secretBits < algorithm.minKeyBits()) {
            throw new IllegalArgumentException(
                    "Le secret JWT doit faire au moins %d bits (%d octets) pour %s, reçu %d bits (%d octets)."
                            .formatted(algorithm.minKeyBits(), algorithm.minKeyBits() / 8,
                                    algorithm, secretBits, secretBytes.length));
        }

        this.algorithm = algorithm;
        this.secretKey = Keys.hmacShaKeyFor(secretBytes);
    }

    /** Raccourci pratique pour l'algorithme par défaut HS256. */
    public static HmacSigningKeyProvider of(String secret) {
        return new HmacSigningKeyProvider(secret, JwtAlgorithm.HS256);
    }

    /** @return l'algorithme HMAC (HS256, HS384 ou HS512) associé à ce provider. */
    @Override
    public JwtAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * @return la clé HMAC dérivée du secret — identique à
     *         {@link #verificationKey()}.
     */
    @Override
    public SecretKey signingKey() {
        return secretKey;
    }

    /**
     * @return la clé HMAC dérivée du secret — identique à {@link #signingKey()}
     *         (HMAC est symétrique).
     */
    @Override
    public SecretKey verificationKey() {
        return secretKey;
    }
}
