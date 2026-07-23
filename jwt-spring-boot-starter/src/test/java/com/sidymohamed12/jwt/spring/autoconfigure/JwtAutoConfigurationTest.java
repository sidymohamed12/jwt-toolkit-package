package com.sidymohamed12.jwt.spring.autoconfigure;

import com.sidymohamed12.jwt.core.claims.ClaimsCustomizer;
import com.sidymohamed12.jwt.core.key.SigningKeyProvider;
import com.sidymohamed12.jwt.core.token.JwtTokenService;
import com.sidymohamed12.jwt.core.token.JwtTokenSpec;
import com.sidymohamed12.jwt.spring.security.JwtAuthenticationConverter;
import com.sidymohamed12.jwt.spring.security.JwtAuthenticationFilter;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class, JwtSecurityAutoConfiguration.class));

    @Test
    void configure_un_jwtTokenService_avec_un_secret_hmac() {
        contextRunner
                .withPropertyValues("jwt.secret=0123456789abcdef0123456789abcdef0123456789abcdef")
                .run((AssertableApplicationContext context) -> {
                    assertThat(context).hasSingleBean(JwtTokenService.class);
                    assertThat(context).hasSingleBean(SigningKeyProvider.class);

                    JwtTokenService service = context.getBean(JwtTokenService.class);
                    String token = service.generate(JwtTokenSpec.builder()
                            .subject("user@example.com")
                            .ttl(Duration.ofMinutes(5))
                            .build());

                    assertThat(service.isValid(token)).isTrue();
                });
    }

    @Test
    void echoue_explicitement_sans_secret_configure() {
        contextRunner.run(context -> assertThat(context).hasFailed());
    }

    @Test
    void applique_un_claimsCustomizer_fourni_par_lapplication() {
        contextRunner
                .withPropertyValues("jwt.secret=0123456789abcdef0123456789abcdef0123456789abcdef")
                .withUserConfiguration(CustomizerConfig.class)
                .run(context -> {
                    JwtTokenService service = context.getBean(JwtTokenService.class);
                    String token = service.generate(JwtTokenSpec.builder()
                            .subject("user@example.com").ttl(Duration.ofMinutes(5)).build());

                    assertThat(service.parse(token).getString("app")).contains("senpna");
                });
    }

    @Test
    void nactive_le_filtre_de_securite_que_si_un_converter_est_fourni() {
        contextRunner
                .withPropertyValues("jwt.secret=0123456789abcdef0123456789abcdef0123456789abcdef")
                .run(context -> assertThat(context).doesNotHaveBean(JwtAuthenticationFilter.class));

        contextRunner
                .withPropertyValues("jwt.secret=0123456789abcdef0123456789abcdef0123456789abcdef")
                .withUserConfiguration(ConverterConfig.class)
                .run(context -> assertThat(context).hasSingleBean(JwtAuthenticationFilter.class));
    }

    @Configuration
    static class CustomizerConfig {
        @Bean
        ClaimsCustomizer appClaimsCustomizer() {
            return builder -> builder.claim("app", "senpna");
        }
    }

    @Configuration
    static class ConverterConfig {
        @Bean
        JwtAuthenticationConverter jwtAuthenticationConverter() {
            return claims -> new UsernamePasswordAuthenticationToken(claims.subject(), null, List.of());
        }
    }
}
