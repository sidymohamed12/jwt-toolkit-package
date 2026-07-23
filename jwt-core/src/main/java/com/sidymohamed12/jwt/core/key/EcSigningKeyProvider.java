package com.sidymohamed12.jwt.core.key;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * {@link SigningKeyProvider} basé sur une paire de clés EC (courbes
 * elliptiques). Alternative à RSA : clés et signatures plus compactes
 * pour un niveau de sécurité équivalent — utile pour des JWT transmis
 * fréquemment (mobile, IoT).
 */
public final class EcSigningKeyProvider implements SigningKeyProvider {

    private final JwtAlgorithm algorithm;
    private final PrivateKey privateKey; // null si provider "vérification seule"
    private final PublicKey publicKey;

    /**
     * @param privateKey clé privée EC utilisée pour signer, ou {@code null} pour un
     *                   provider "vérification seule"
     * @param publicKey  clé publique EC utilisée pour vérifier (obligatoire)
     * @param algorithm  algorithme EC à utiliser (ES256, ES384 ou ES512)
     * @throws NullPointerException     si {@code publicKey} ou {@code algorithm}
     *                                  est {@code null}
     * @throws IllegalArgumentException si {@code algorithm} n'est pas de la famille
     *                                  EC
     */
    public EcSigningKeyProvider(PrivateKey privateKey, PublicKey publicKey, JwtAlgorithm algorithm) {
        Objects.requireNonNull(publicKey, "publicKey ne peut pas être null");
        Objects.requireNonNull(algorithm, "algorithm ne peut pas être null");
        if (algorithm.family() != JwtAlgorithm.Family.EC) {
            throw new IllegalArgumentException(
                    "EcSigningKeyProvider ne supporte que les algorithmes EC, reçu : " + algorithm);
        }

        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.algorithm = algorithm;
    }

    /**
     * Provider "vérification seule" : microservice consommateur sans capacité de
     * signature
     * (toute tentative d'appel à {@link #signingKey()} lève une
     * {@link IllegalStateException}).
     *
     * @param publicKey clé publique EC utilisée pour vérifier les tokens
     * @param algorithm algorithme EC à utiliser (ES256, ES384 ou ES512)
     */
    public static EcSigningKeyProvider verificationOnly(PublicKey publicKey, JwtAlgorithm algorithm) {
        return new EcSigningKeyProvider(null, publicKey, algorithm);
    }

    /**
     * Construit un provider à partir de clés encodées en Base64
     * (PKCS8 pour la clé privée, X509 pour la clé publique).
     *
     * @param privateKeyBase64 peut être {@code null}/vide pour un provider
     *                         "vérification seule"
     * @param publicKeyBase64  obligatoire
     * @param algorithm        algorithme EC à utiliser (ES256, ES384 ou ES512)
     * @throws IllegalArgumentException si les clés sont invalides ou mal encodées
     */
    public static EcSigningKeyProvider fromBase64(String privateKeyBase64, String publicKeyBase64,
            JwtAlgorithm algorithm) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PrivateKey priv = null;
            if (privateKeyBase64 != null && !privateKeyBase64.isBlank()) {
                byte[] privBytes = Base64.getDecoder().decode(stripPemHeaders(privateKeyBase64));
                priv = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
            }
            Objects.requireNonNull(publicKeyBase64, "publicKeyBase64 est obligatoire");
            byte[] pubBytes = Base64.getDecoder().decode(stripPemHeaders(publicKeyBase64));
            PublicKey pub = keyFactory.generatePublic(new X509EncodedKeySpec(pubBytes));
            return new EcSigningKeyProvider(priv, pub, algorithm);
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Clés EC invalides ou mal encodées.", e);
        }
    }

    /**
     * Retire les en-têtes PEM ({@code -----BEGIN/END...-----}) et les espaces, ne
     * garde que le Base64 brut.
     */
    private static String stripPemHeaders(String pem) {
        return pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
    }

    /** @return l'algorithme EC (ES256, ES384 ou ES512) associé à ce provider. */
    @Override
    public JwtAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * @return la clé privée EC utilisée pour signer.
     * @throws IllegalStateException si ce provider est en mode "vérification seule"
     *                               (construit via
     *                               {@link #verificationOnly(PublicKey, JwtAlgorithm)})
     */
    @Override
    public PrivateKey signingKey() {
        if (privateKey == null) {
            throw new IllegalStateException(
                    "Ce provider EC est en mode vérification seule : aucune clé privée disponible pour signer.");
        }
        return privateKey;
    }

    /** @return la clé publique EC utilisée pour vérifier les tokens. */
    @Override
    public PublicKey verificationKey() {
        return publicKey;
    }
}
