package com.errday.springsecurityoauthstudy.config;

import com.errday.springsecurityoauthstudy.filter.CustomOAuth2LoginAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

@Configuration
public class OAuth2ClientConfig {

    @Autowired
    private DefaultOAuth2AuthorizedClientManager authorizedClientManager;
    @Autowired
    private OAuth2AuthorizedClientRepository authorizedClientRepository;

    private final String[] whiteList = {
            "/",
            "/oauth2Login/password-flow",
            "/oauth2Login/client-credentials-flow",
            "/oauth2Login/v2/password-flow",
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
        http.addFilterAfter(customOAuth2AuthenticationFilter(), AnonymousAuthenticationFilter.class);
        return http.build();
    }

    private CustomOAuth2LoginAuthenticationFilter customOAuth2AuthenticationFilter() {
        CustomOAuth2LoginAuthenticationFilter auth2AuthenticationFilter = new CustomOAuth2LoginAuthenticationFilter(authorizedClientManager, authorizedClientRepository);
        auth2AuthenticationFilter.setSecurityContextRepository(new HttpSessionSecurityContextRepository());
        auth2AuthenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> response.sendRedirect("/home"));
        return auth2AuthenticationFilter;
    }

}
