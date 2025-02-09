package com.errday.springsecurityoauthstudy;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            //.httpBasic(withDefaults())
            .httpBasic(httpBasic -> httpBasic.authenticationEntryPoint(new CustomAuthenticationEntryPoint()))
        ;
        //new CustomSecurityConfigurer().setFlag(true).configure(http);
        return http.build();
    }
}
