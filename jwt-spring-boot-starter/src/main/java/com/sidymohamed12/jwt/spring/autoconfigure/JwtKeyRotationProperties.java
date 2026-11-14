package com.sidymohamed12.jwt.spring.autoconfigure;

import com.sidymohamed12.jwt.core.algorithm.JwtAlgorithm;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Configuration de la rotation des clés JWT, sous le préfixe
 * {@code jwt.rotation}.
 * <p>
 * La clé <strong>active</strong> reste celle décrite par {@link JwtProperties}
 * ({@code jwt.secret}, {@code jwt.rsa.*} ou {@code jwt.ec.*}) ;
 * {@code active-key-id} lui donne seulement un identifiant ({@code kid}). Les
 * clés précédentes ne servent qu'à vérifier les tokens encore en circulation.
 *
 * <pre>{@code
 * jwt:
 *   algorithm: HS256
 *   secret: ${JWT_SECRET}
 *   rotation:
 *     active-key-id: "2026-11"
 *     previous-keys:
 *       - key-id: "2026-10"
 *         secret: ${JWT_SECRET_PREVIOUS}
 * }</pre>
 *
 * @param activeKeyId  identifiant ({@code kid}) de la clé active ; absent = pas
 *                     de {@code kid} (mode clé unique, comportement historique)
 * @param previousKeys clés précédentes, en vérification seule
 */
@ConfigurationProperties(prefix = "jwt.rotation")
public record JwtKeyRotationProperties(String activeKeyId, List<PreviousKey> previousKeys) {

    /**
     * Normalise {@code previousKeys} : {@code null} devient une liste vide.
     *
     * @param activeKeyId  voir la documentation du record
     * @param previousKeys voir la documentation du record
     */
    public JwtKeyRotationProperties {
        previousKeys = previousKeys == null ? List.of() : List.copyOf(previousKeys);
    }

    /**
     * Clé précédente, utilisée uniquement pour vérifier les tokens qui portent son
     * {@code kid}.
     *
     * @param keyId     identifiant ({@code kid}) de la clé, obligatoire et unique
     * @param algorithm algorithme de cette clé ; absent = même algorithme que
     *                  {@code jwt.algorithm}
     * @param secret    secret HMAC (famille HMAC)
     * @param publicKey clé publique Base64/PEM (familles RSA et EC)
     */
    public record PreviousKey(String keyId, JwtAlgorithm algorithm, String secret, String publicKey) {
    }
}
