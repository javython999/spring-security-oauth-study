package com.errday.oauth2resourceserver.config;


import com.errday.oauth2resourceserver.filter.authentication.JwtAuthenticationFilter;
import com.errday.oauth2resourceserver.filter.authorization.JwtAuthorizationRsaPublicKeyFilter;
import com.errday.oauth2resourceserver.signature.RsaPublicKeySecuritySigner;
import com.errday.oauth2resourceserver.signature.RsaSecuritySigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class OAuth2ResourceServerConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable);

        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers("/").permitAll()
                .anyRequest().authenticated()
        );
        http.userDetailsService(userDetailsService());
        http.addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class);
        //http.addFilterBefore(jwtAuthorizationMacFilter(null), UsernamePasswordAuthenticationFilter.class);
        //http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwtConfigurer -> jwtConfigurer.decoder(jwtDecoderBySecretKey)));
        //http.addFilterBefore(jwtAuthorizationRsaFilter(null), UsernamePasswordAuthenticationFilter.class);

        http.addFilterBefore(jwtAuthorizationRsaPublicKeyFilter(null), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public JwtAuthorizationRsaPublicKeyFilter jwtAuthorizationRsaPublicKeyFilter(JwtDecoder jwtDecoder) throws JOSEException {
        return new JwtAuthorizationRsaPublicKeyFilter(jwtDecoder);
    }

   /* @Bean
    public JwtAuthorizationRsaFilter jwtAuthorizationRsaFilter(RSAKey rsaKey) throws JOSEException {
        return new JwtAuthorizationRsaFilter(new RSASSAVerifier(rsaKey.toRSAPublicKey()));
    }*/

    /*@Bean
    public JwtAuthorizationMacFilter jwtAuthorizationMacFilter(OctetSequenceKey octetSequenceKey) throws JOSEException {
        return new JwtAuthorizationMacFilter(new MACVerifier(octetSequenceKey.toSecretKey()));
    }*/

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(RsaPublicKeySecuritySigner rsaPublicKeySecuritySigner, RSAKey rsaKey) throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(rsaPublicKeySecuritySigner,rsaKey);
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
        return jwtAuthenticationFilter;
    }

    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails user = User.withUsername("user").password("1234").authorities("ROLE_USER").build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
}
