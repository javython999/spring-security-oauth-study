package com.errday.springsecurityoauthstudy.config;

import com.errday.springsecurityoauthstudy.CustomAuthorityMapper;
import com.errday.springsecurityoauthstudy.service.CustomOAuth2UserService;
import com.errday.springsecurityoauthstudy.service.CustomOidcUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@RequiredArgsConstructor
public class OAuth2ClientConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOidcUserService customOidcUserService;

    private final String[] whiteList = {
            "/",
            "/favicon.ico",
            "/error",
            "/js/**",
            "/css/**",
    };


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                //.requestMatchers("/api/user").hasAnyAuthority("SCOPE_profile", "SCOPE_email")
                .requestMatchers("/api/user").hasAnyAuthority("ROLE_profile", "ROLE_email")
                .requestMatchers("/api/oidc").hasAnyAuthority("SCOPE_openid")
                .requestMatchers(whiteList).permitAll()
                .anyRequest().authenticated()
        );
        http.oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                        .userService(customOAuth2UserService)
                        .oidcUserService(customOidcUserService)
                )
        );
        http.logout(logout -> logout.logoutSuccessUrl("/"));
        return http.build();
    }

    @Bean
    public GrantedAuthoritiesMapper customAuthoritiesMapper() {
        return new CustomAuthorityMapper();
    }

}
