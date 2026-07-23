package com.sidymohamed12.jwt.core.claims;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Représentation immuable des informations portées par un JWT décodé.
 * <p>
 * Fournit des accesseurs typés pour les champs personnalisés ajoutés par
 * chaque projet consommateur (ex : {@code entrepotId}, {@code tenantId},
 * {@code roles}...), sans que la librairie n'ait à connaître leur nature
 * métier — c'est le cœur de la "personnalisation des champs".
 */
public final class JwtClaims {

    private final String subject;
    private final String tokenId;
    private final Instant issuedAt;
    private final Instant expiration;
    private final Map<String, Object> customClaims;

    /**
     * @param subject      claim standard {@code sub}
     * @param tokenId      claim standard {@code jti}, ou {@code null} si absent du
     *                     token
     * @param issuedAt     claim standard {@code iat}, ou {@code null} si absent du
     *                     token
     * @param expiration   claim standard {@code exp}, ou {@code null} si absent du
     *                     token
     * @param customClaims tous les autres claims (personnalisés), sous forme brute
     */
    public JwtClaims(String subject, String tokenId, Instant issuedAt, Instant expiration,
            Map<String, Object> customClaims) {
        this.subject = subject;
        this.tokenId = tokenId;
        this.issuedAt = issuedAt;
        this.expiration = expiration;
        this.customClaims = Collections.unmodifiableMap(customClaims);
    }

    /**
     * @return le claim standard {@code sub} (sujet du token, généralement
     *         l'identifiant de l'utilisateur).
     */
    public String subject() {
        return subject;
    }

    /**
     * @return le claim standard {@code jti} (identifiant unique du token), s'il a
     *         été demandé à la génération.
     */
    public Optional<String> tokenId() {
        return Optional.ofNullable(tokenId);
    }

    /** @return la date d'émission du token (claim standard {@code iat}). */
    public Instant issuedAt() {
        return issuedAt;
    }

    /** @return la date d'expiration du token (claim standard {@code exp}). */
    public Instant expiration() {
        return expiration;
    }

    /**
     * @param reference instant de référence auquel comparer l'expiration
     *                  (généralement {@code Instant.now()})
     * @return {@code true} si {@link #expiration()} est antérieure à
     *         {@code reference}.
     */
    public boolean isExpired(Instant reference) {
        return expiration != null && expiration.isBefore(reference);
    }

    /** Vue brute, non modifiable, de tous les claims personnalisés. */
    public Map<String, Object> customClaims() {
        return customClaims;
    }

    /**
     * @return la valeur brute (non typée) du claim personnalisé nommé {@code name},
     *         si présent.
     */
    public Optional<Object> get(String name) {
        return Optional.ofNullable(customClaims.get(name));
    }

    /**
     * @return le claim {@code name} converti en {@link String} via
     *         {@code String.valueOf}, si présent.
     */
    public Optional<String> getString(String name) {
        return get(name).map(String::valueOf);
    }

    /**
     * @return le claim {@code name} interprété comme un {@link UUID}, si présent.
     * @throws IllegalArgumentException si la valeur du claim n'est pas un UUID
     *                                  valide
     */
    public Optional<UUID> getUUID(String name) {
        return getString(name).map(UUID::fromString);
    }

    /**
     * @return le claim {@code name} interprété comme un {@link Long}, si présent
     *         (accepte un nombre JSON natif ou une chaîne numérique).
     */
    public Optional<Long> getLong(String name) {
        return get(name).map(v -> v instanceof Number n ? n.longValue() : Long.parseLong(String.valueOf(v)));
    }

    /**
     * @return le claim {@code name} interprété comme un {@link Integer}, si présent
     *         (accepte un nombre JSON natif ou une chaîne numérique).
     */
    public Optional<Integer> getInt(String name) {
        return get(name).map(v -> v instanceof Number n ? n.intValue() : Integer.parseInt(String.valueOf(v)));
    }

    /**
     * @return le claim {@code name} interprété comme un {@link Boolean}, si
     *         présent.
     */
    public Optional<Boolean> getBoolean(String name) {
        return get(name).map(v -> v instanceof Boolean b ? b : Boolean.parseBoolean(String.valueOf(v)));
    }

    /** Interprète un claim numérique (secondes epoch) comme un {@link Instant}. */
    public Optional<Instant> getInstant(String name) {
        return getLong(name).map(Instant::ofEpochSecond);
    }

    /**
     * Pratique pour les claims de type liste (ex : {@code roles}), quel que soit
     * leur type JSON
     * d'origine (tableau, valeur unique...).
     *
     * @return l'ensemble des valeurs du claim {@code name} converties en
     *         {@link String},
     *         ou un ensemble vide si le claim est absent.
     */
    public Set<String> getStringSet(String name) {
        Object value = customClaims.get(name);
        if (value == null) {
            return Collections.emptySet();
        }
        if (value instanceof Iterable<?> iterable) {
            Set<String> result = new HashSet<>();
            iterable.forEach(o -> result.add(String.valueOf(o)));
            return result;
        }
        return Set.of(String.valueOf(value));
    }

    /**
     * Extrait un claim personnalisé et le caste vers le type demandé.
     *
     * @param name le nom du claim
     * @param type la classe cible attendue
     * @return le claim casté vers {@code type}, ou {@link Optional#empty()} si
     *         absent
     * @throws ClassCastException si la valeur présente n'est pas une instance de
     *                            {@code type}
     */
    public <T> Optional<T> getAs(String name, Class<T> type) {
        Object value = customClaims.get(name);
        if (value == null) {
            return Optional.empty();
        }
        if (type.isInstance(value)) {
            return Optional.of(type.cast(value));
        }
        throw new ClassCastException(
                "Le claim '%s' est de type %s, incompatible avec %s demandé."
                        .formatted(name, value.getClass(), type));
    }
}
