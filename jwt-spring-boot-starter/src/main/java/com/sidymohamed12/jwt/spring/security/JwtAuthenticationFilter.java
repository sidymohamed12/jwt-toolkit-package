package com.sidymohamed12.jwt.spring.security;

import com.sidymohamed12.jwt.core.claims.JwtClaims;
import com.sidymohamed12.jwt.core.exception.JwtValidationException;
import com.sidymohamed12.jwt.core.token.JwtTokenService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtre optionnel : authentifie la requête à partir d'un en-tête
 * {@code Authorization: Bearer <token>}.
 * <p>
 * Volontairement <strong>non</strong> enregistré automatiquement dans une
 * {@code SecurityFilterChain} — chaque application a sa propre
 * configuration de sécurité (ordre des filtres, endpoints publics...).
 * Récupérez ce bean et ajoutez-le vous-même :
 *
 * <pre>{@code
 * http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
 * }</pre>
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtTokenService jwtTokenService;
    private final JwtAuthenticationConverter authenticationConverter;

    /**
     * @param jwtTokenService         utilisé pour parser/valider le token reçu
     * @param authenticationConverter convertit les claims validés en
     *                                {@code Authentication}
     */
    public JwtAuthenticationFilter(JwtTokenService jwtTokenService,
            JwtAuthenticationConverter authenticationConverter) {
        this.jwtTokenService = jwtTokenService;
        this.authenticationConverter = authenticationConverter;
    }

    /**
     * Lit l'en-tête {@code Authorization}, valide le token s'il est présent, et
     * peuple le
     * {@code SecurityContext} si aucune authentification n'est déjà en place. Ne
     * bloque
     * jamais la chaîne de filtres : un token absent ou invalide laisse simplement
     * la requête
     * non authentifiée (à charge des règles d'autorisation de la rejeter si
     * nécessaire).
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(BEARER_PREFIX.length());
        try {
            JwtClaims claims = jwtTokenService.parse(token);
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                Authentication authentication = authenticationConverter.convert(claims);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (JwtValidationException e) {
            log.debug("[JWT] Token invalide : {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}
