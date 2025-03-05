package com.errday.oauthclientapp;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

@Configuration
public class OAuth2ClientConfig {

    private final String[] whiteList = {
            "/",
            "/favicon.ico",
            "/error",
    };

    @Bean
    public SecurityFilterChain securityContextHolder(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(whiteList).permitAll()
                .anyRequest().authenticated()
        );

        http.oauth2Login(oauth2Login -> oauth2Login
                .defaultSuccessUrl("/")
        );

        http.oauth2Client(oauth2Client -> Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
