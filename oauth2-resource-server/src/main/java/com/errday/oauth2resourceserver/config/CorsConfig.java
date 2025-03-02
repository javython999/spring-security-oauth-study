package com.errday.oauth2resourceserver.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // 인증 처리 허용
        config.addAllowedOriginPattern("*"); // 도메인 허용
        config.addAllowedHeader("*"); // 헤더 허용
        config.addAllowedMethod("*"); // http method 허용

        source.registerCorsConfiguration("/api/**", config);

        return new CorsFilter(source);
    }
}
