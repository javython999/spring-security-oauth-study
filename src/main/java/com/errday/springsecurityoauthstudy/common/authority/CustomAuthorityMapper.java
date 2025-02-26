package com.errday.springsecurityoauthstudy.common.authority;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.Collection;
import java.util.HashSet;

@Slf4j
public class CustomAuthorityMapper implements GrantedAuthoritiesMapper {

    private String prefix = "ROLE_";

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {

        HashSet<GrantedAuthority> mapped = new HashSet<>(authorities);

        for (GrantedAuthority authority : authorities) {
            mapped.add(mapAuthorities(authority.getAuthority()));
        }

        return mapped;
    }

    private GrantedAuthority mapAuthorities(String authority) {

        if(authority.lastIndexOf(".") > 0){
            int index = authority.lastIndexOf(".");
            authority = "SCOPE_" + authority.substring(index+1);
        }
        if (!this.prefix.isEmpty() && !authority.startsWith(this.prefix)) {
            authority = this.prefix + authority;
        }

        return new SimpleGrantedAuthority(authority);
    }
}
