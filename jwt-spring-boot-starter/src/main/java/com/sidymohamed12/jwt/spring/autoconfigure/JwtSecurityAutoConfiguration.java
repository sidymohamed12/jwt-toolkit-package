package com.sidymohamed12.jwt.spring.autoconfigure;

import com.sidymohamed12.jwt.core.token.JwtTokenService;
import com.sidymohamed12.jwt.spring.security.JwtAuthenticationConverter;
import com.sidymohamed12.jwt.spring.security.JwtAuthenticationFilter;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Active {@link JwtAuthenticationFilter} uniquement si :
 * <ol>
 * <li>Spring Security est présent sur le classpath (dépendance optionnelle
 * de ce starter) ;</li>
 * <li>le projet consommateur a fourni un bean
 * {@link JwtAuthenticationConverter}
 * — sans lui, la librairie ne saurait pas construire une
 * {@code Authentication} cohérente avec le modèle de rôles propre à
 * l'application.</li>
 * </ol>
 */
@AutoConfiguration
@AutoConfigureAfter(JwtAutoConfiguration.class)
@ConditionalOnClass(UsernamePasswordAuthenticationFilter.class)
public class JwtSecurityAutoConfiguration {

    /**
     * @return un {@link JwtAuthenticationFilter} prêt à être ajouté manuellement à
     *         votre
     *         {@code SecurityFilterChain} ; n'existe que si un
     *         {@link JwtAuthenticationConverter}
     *         est présent dans le contexte.
     */
    @Bean
    @ConditionalOnBean(JwtAuthenticationConverter.class)
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtTokenService jwtTokenService,
            JwtAuthenticationConverter converter) {
        return new JwtAuthenticationFilter(jwtTokenService, converter);
    }
}
