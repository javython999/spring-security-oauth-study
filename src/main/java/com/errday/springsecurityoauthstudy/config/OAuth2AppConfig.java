package com.errday.springsecurityoauthstudy.config;

import com.errday.springsecurityoauthstudy.common.authority.CustomAuthorityMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

@Configuration
public class OAuth2AppConfig {

    @Bean
    public GrantedAuthoritiesMapper customAuthoritiesMapper() {
        return new CustomAuthorityMapper();
    }
}
