package com.errday.oauth2resourceserver.config;


import com.errday.oauth2resourceserver.filter.authentication.JwtAuthenticationFilter;
import com.errday.oauth2resourceserver.filter.authorization.JwtAuthorizationRsaPublicKeyFilter;
import com.errday.oauth2resourceserver.opaquetoken.CustomOpaqueTokenIntrospector;
import com.errday.oauth2resourceserver.signature.RsaPublicKeySecuritySigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class OAuth2ResourceServerConfig {

    @Autowired
    private OAuth2ResourceServerProperties properties;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {


        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .anyRequest().authenticated()
        );
        //http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken);
        http.oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer ->
                httpSecurityOAuth2ResourceServerConfigurer.opaqueToken(
                        opaqueTokenConfigurer -> customOpaqueTokenIntrospector(properties)
                ));
        return http.build();
    }

    /*@Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector(OAuth2ResourceServerProperties properties) {
        OAuth2ResourceServerProperties.Opaquetoken opaquetoken = properties.getOpaquetoken();
        return new NimbusOpaqueTokenIntrospector(opaquetoken.getIntrospectionUri(), opaquetoken.getClientId(), opaquetoken.getClientSecret());
    }*/

    @Bean
    public OpaqueTokenIntrospector customOpaqueTokenIntrospector(OAuth2ResourceServerProperties properties) {
        return new CustomOpaqueTokenIntrospector(properties);
    }

    /*@Bean
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

        //http.addFilterBefore(jwtAuthorizationRsaPublicKeyFilter(null), UsernamePasswordAuthenticationFilter.class);

        http.oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> httpSecurityOAuth2ResourceServerConfigurer.jwt());
        return http.build();
    }*/

    //@Bean
    public SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new CustomRoleConverter());

        http.csrf(AbstractHttpConfigurer::disable);

        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers("/photos/1").hasAuthority("ROLE_photo")
                .requestMatchers("/photos/3").hasAuthority("ROLE_default-roles-oauth2")
                .anyRequest().authenticated()
        );
        http.userDetailsService(userDetailsService());
        http.addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class);

        //http.oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> httpSecurityOAuth2ResourceServerConfigurer.jwt());
        http.oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> httpSecurityOAuth2ResourceServerConfigurer
                .jwt().jwtAuthenticationConverter(jwtAuthenticationConverter)
        );
        return http.build();
    }

    //@Bean
    public SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable);

        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers("/photos/2").permitAll()
                .anyRequest().authenticated()
        );
        http.userDetailsService(userDetailsService());
        http.addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class);
        http.oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> httpSecurityOAuth2ResourceServerConfigurer.jwt());
        return http.build();
    }

    //@Bean
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

    //@Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    //@Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(RsaPublicKeySecuritySigner rsaPublicKeySecuritySigner, RSAKey rsaKey) throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(rsaPublicKeySecuritySigner,rsaKey);
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
        return jwtAuthenticationFilter;
    }

    //@Bean
    public UserDetailsService userDetailsService(){

        UserDetails user = User.withUsername("user").password("1234").authorities("ROLE_USER").build();
        return new InMemoryUserDetailsManager(user);
    }

    //@Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
}
