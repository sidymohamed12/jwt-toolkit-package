package com.sidymohamed12.jwt.core.key;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Trousseau de clés permettant la <strong>rotation</strong> sans invalider les
 * tokens déjà émis.
 * <p>
 * Il contient :
 * <ul>
 * <li>une clé <strong>active</strong>, la seule utilisée pour signer les
 * nouveaux tokens — son identifiant ({@code kid}) est écrit dans l'en-tête de
 * chaque token émis ;</li>
 * <li>zéro ou plusieurs clés <strong>précédentes</strong>, utilisées
 * uniquement pour vérifier les tokens encore en circulation qui portent leur
 * {@code kid} (jamais pour signer).</li>
 * </ul>
 * Chaque clé garde son propre {@link SigningKeyProvider#algorithm()
 * algorithme} : un token n'est accepté que si l'algorithme déclaré dans son
 * en-tête est exactement celui de la clé désignée par son {@code kid}.
 *
 * <h2>Résolution d'une clé à partir du {@code kid}</h2>
 * <ul>
 * <li>token sans {@code kid} → clé active ;</li>
 * <li>{@code kid} connu (actif ou précédent) → clé correspondante ;</li>
 * <li>{@code kid} inconnu → aucune clé (token refusé), sauf en mode clé
 * unique ({@link #of(SigningKeyProvider)}) où il n'y a qu'une clé possible :
 * la clé active est alors utilisée.</li>
 * </ul>
 *
 * <pre>{@code
 * SigningKeyRing ring = SigningKeyRing.builder()
 *         .active("2026-11", new HmacSigningKeyProvider(newSecret, JwtAlgorithm.HS256))
 *         .previous("2026-10", new HmacSigningKeyProvider(oldSecret, JwtAlgorithm.HS256))
 *         .build();
 * }</pre>
 */
public final class SigningKeyRing {

    private static final String PROVIDER_REQUIRED = "provider ne peut pas être null";

    private final String activeKeyId;
    private final SigningKeyProvider active;
    private final Map<String, SigningKeyProvider> keysById;

    private SigningKeyRing(String activeKeyId, SigningKeyProvider active, Map<String, SigningKeyProvider> keysById) {
        this.activeKeyId = activeKeyId;
        this.active = active;
        this.keysById = Collections.unmodifiableMap(keysById);
    }

    /**
     * Crée un trousseau à clé unique, sans {@code kid} (comportement historique
     * de la librairie).
     *
     * @param active la clé de signature/vérification
     * @return un trousseau ne contenant que cette clé
     * @throws NullPointerException si {@code active} est {@code null}
     */
    public static SigningKeyRing of(SigningKeyProvider active) {
        return builder().active(active).build();
    }

    /** @return un nouveau builder de trousseau. */
    public static Builder builder() {
        return new Builder();
    }

    /** @return la clé active, utilisée pour signer les nouveaux tokens. */
    public SigningKeyProvider active() {
        return active;
    }

    /**
     * @return le {@code kid} de la clé active, ou {@link Optional#empty()} si la
     *         clé active n'a pas d'identifiant (mode clé unique)
     */
    public Optional<String> activeKeyId() {
        return Optional.ofNullable(activeKeyId);
    }

    /**
     * Résout la clé à utiliser pour vérifier un token, à partir du {@code kid}
     * lu dans son en-tête (voir les règles dans la documentation de la classe).
     *
     * @param keyId le {@code kid} du token, ou {@code null} s'il n'en a pas
     * @return la clé correspondante, ou {@link Optional#empty()} si le
     *         {@code kid} est inconnu
     */
    public Optional<SigningKeyProvider> find(String keyId) {
        if (keyId == null) {
            return Optional.of(active);
        }
        SigningKeyProvider provider = keysById.get(keyId);
        if (provider != null) {
            return Optional.of(provider);
        }
        return keysById.isEmpty() ? Optional.of(active) : Optional.empty();
    }

    /** Builder de {@link SigningKeyRing}. */
    public static final class Builder {

        private String activeKeyId;
        private SigningKeyProvider active;
        private final Map<String, SigningKeyProvider> previous = new LinkedHashMap<>();

        private Builder() {
        }

        /**
         * Définit la clé active sans identifiant ({@code kid}). Incompatible
         * avec l'ajout de clés précédentes.
         *
         * @param provider la clé active
         * @return ce builder
         */
        public Builder active(SigningKeyProvider provider) {
            this.activeKeyId = null;
            this.active = Objects.requireNonNull(provider, PROVIDER_REQUIRED);
            return this;
        }

        /**
         * Définit la clé active et son identifiant, écrit dans l'en-tête
         * {@code kid} de chaque token émis.
         *
         * @param keyId    identifiant de la clé (non vide)
         * @param provider la clé active
         * @return ce builder
         * @throws IllegalArgumentException si {@code keyId} est vide
         */
        public Builder active(String keyId, SigningKeyProvider provider) {
            this.activeKeyId = requireKeyId(keyId);
            this.active = Objects.requireNonNull(provider, PROVIDER_REQUIRED);
            return this;
        }

        /**
         * Ajoute une clé précédente, utilisée uniquement pour vérifier les
         * tokens qui portent son {@code kid}.
         *
         * @param keyId    identifiant de la clé (non vide, unique)
         * @param provider la clé (seule sa clé de vérification est utilisée)
         * @return ce builder
         * @throws IllegalArgumentException si {@code keyId} est vide ou déjà
         *                                  utilisé
         */
        public Builder previous(String keyId, SigningKeyProvider provider) {
            String id = requireKeyId(keyId);
            Objects.requireNonNull(provider, PROVIDER_REQUIRED);
            if (previous.putIfAbsent(id, provider) != null) {
                throw new IllegalArgumentException(duplicateMessage(id));
            }
            return this;
        }

        /**
         * @return le trousseau construit
         * @throws IllegalStateException    si aucune clé active n'est définie, ou
         *                                  si des clés précédentes sont déclarées
         *                                  alors que la clé active n'a pas de
         *                                  {@code kid}
         * @throws IllegalArgumentException si le {@code kid} actif est aussi
         *                                  déclaré comme clé précédente
         */
        public SigningKeyRing build() {
            if (active == null) {
                throw new IllegalStateException("Une clé active est obligatoire.");
            }
            if (activeKeyId == null && !previous.isEmpty()) {
                throw new IllegalStateException(
                        "La clé active doit avoir un identifiant (kid) dès qu'il existe des clés précédentes.");
            }
            if (activeKeyId != null && previous.containsKey(activeKeyId)) {
                throw new IllegalArgumentException(duplicateMessage(activeKeyId));
            }

            Map<String, SigningKeyProvider> keysById = new LinkedHashMap<>();
            if (activeKeyId != null) {
                keysById.put(activeKeyId, active);
            }
            keysById.putAll(previous);
            return new SigningKeyRing(activeKeyId, active, keysById);
        }

        private static String requireKeyId(String keyId) {
            if (keyId == null || keyId.isBlank()) {
                throw new IllegalArgumentException("keyId (kid) ne peut pas être vide.");
            }
            return keyId;
        }

        private static String duplicateMessage(String keyId) {
            return "keyId (kid) déjà utilisé dans le trousseau : " + keyId;
        }
    }
}
