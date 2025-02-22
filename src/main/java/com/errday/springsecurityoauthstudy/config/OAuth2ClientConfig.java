package com.errday.springsecurityoauthstudy.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class OAuth2ClientConfig {

    private final String[] whiteList = {
            "/",
            "/oauth2Login",
            "/oauth2Login-password-flow",
            "oauth2Login-client-credentials-flow",
            "/client",
            "/favicon.ico",
            "/error"
    };

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers(whiteList).permitAll()
                .anyRequest().authenticated()
        );
        http.oauth2Client(Customizer.withDefaults());
        return http.build();
    }

}
