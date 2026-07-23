package com.sidymohamed12.jwt.core.token;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Spécification d'un token à générer : sujet, durée de vie et champs
 * personnalisés. Point d'entrée principal pour la "personnalisation des
 * champs" côté appelant — chaque projet consommateur ajoute exactement
 * les claims dont il a besoin ({@code entrepotId}, {@code tenantId},
 * {@code roles}, {@code type=refresh}...) sans que la librairie n'ait à
 * les connaître à l'avance.
 *
 * <pre>{@code
 * JwtTokenSpec spec = JwtTokenSpec.builder()
 *         .subject(user.getEmail())
 *         .ttl(Duration.ofMinutes(15))
 *         .claim("roles", Set.of("ADMIN"))
 *         .claim("entrepotId", entrepotId)
 *         .autoTokenId()
 *         .build();
 * }</pre>
 */
public final class JwtTokenSpec {

    private final String subject;
    private final Map<String, Object> claims;
    private final Duration ttl;
    private final String tokenId;

    private JwtTokenSpec(Builder builder) {
        this.subject = builder.subject;
        this.claims = Map.copyOf(builder.claims);
        this.ttl = builder.ttl;
        this.tokenId = builder.tokenId;
    }

    /** @return le sujet du token (claim standard {@code sub}). */
    public String subject() {
        return subject;
    }

    /** @return les claims personnalisés explicitement ajoutés via le builder. */
    public Map<String, Object> claims() {
        return claims;
    }

    /**
     * @return la durée de vie demandée pour le token (utilisée pour calculer le
     *         claim {@code exp}).
     */
    public Duration ttl() {
        return ttl;
    }

    /** Valeur du claim standard {@code jti}, ou {@code null} si non demandé. */
    public String tokenId() {
        return tokenId;
    }

    /** @return un nouveau builder pour construire une spécification de token. */
    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String subject;
        private final Map<String, Object> claims = new LinkedHashMap<>();
        private Duration ttl;
        private String tokenId;

        private Builder() {
        }

        /** Définit le sujet du token (claim standard {@code sub}) — obligatoire. */
        public Builder subject(String subject) {
            this.subject = subject;
            return this;
        }

        /**
         * Définit la durée de vie du token — obligatoire, doit être strictement
         * positive.
         */
        public Builder ttl(Duration ttl) {
            this.ttl = ttl;
            return this;
        }

        /**
         * Définit explicitement le claim standard {@code jti} (identifiant unique du
         * token).
         */
        public Builder tokenId(String tokenId) {
            this.tokenId = tokenId;
            return this;
        }

        /**
         * Génère un {@code jti} aléatoire (UUID) — utile pour la traçabilité ou la
         * révocation ciblée.
         */
        public Builder autoTokenId() {
            this.tokenId = UUID.randomUUID().toString();
            return this;
        }

        /**
         * Ajoute un claim personnalisé ; ignoré silencieusement si {@code value} est
         * {@code null}.
         */
        public Builder claim(String name, Object value) {
            if (value != null) {
                claims.put(name, value);
            }
            return this;
        }

        /**
         * Ajoute un claim UUID, sérialisé en chaîne de caractères ; ignoré si
         * {@code value} est {@code null}.
         */
        public Builder claim(String name, UUID value) {
            return claim(name, value == null ? null : value.toString());
        }

        /** Ajoute plusieurs claims personnalisés en une fois. */
        public Builder claims(Map<String, Object> extra) {
            if (extra != null) {
                claims.putAll(extra);
            }
            return this;
        }

        /**
         * @return la spécification construite, prête à être passée à
         *         {@code JwtTokenService.generate}.
         * @throws IllegalStateException si le subject est manquant ou vide, ou si le
         *                               ttl est nul/négatif
         */
        public JwtTokenSpec build() {
            if (subject == null || subject.isBlank()) {
                throw new IllegalStateException("Le subject est obligatoire pour générer un JWT.");
            }
            if (ttl == null || ttl.isNegative() || ttl.isZero()) {
                throw new IllegalStateException("Le ttl doit être strictement positif.");
            }
            return new JwtTokenSpec(this);
        }
    }
}
