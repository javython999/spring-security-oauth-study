package com.errday.oauth2resourceserver;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class OAuth2ResourceServerConfig {

    @Autowired
    OAuth2ResourceServerProperties properties;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated());
        //http.oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(Customizer.withDefaults()));
        http.oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(jwtConfigurer -> jwtConfigurer.decoder(jwtDecoder3())));
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder1() {
        return JwtDecoders.fromIssuerLocation(properties.getJwt().getIssuerUri());
    }

    @Bean
    public JwtDecoder jwtDecoder2() {
        return JwtDecoders.fromOidcIssuerLocation(properties.getJwt().getIssuerUri()) ;
    }

    @Bean
    public JwtDecoder jwtDecoder3() {
        return NimbusJwtDecoder.withJwkSetUri(properties.getJwt().getJwkSetUri())
                .build();
    }
}
