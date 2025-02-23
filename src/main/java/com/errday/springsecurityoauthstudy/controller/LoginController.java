package com.errday.springsecurityoauthstudy.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Set;

@Controller
@RequiredArgsConstructor
public class LoginController {

    private final DefaultOAuth2AuthorizedClientManager authorizedClientManager;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    @GetMapping("/oauth2Login/password-flow")
    public String oauth2LoginPasswordFlow(HttpServletRequest request, HttpServletResponse response, Model model) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("keycloak")
                .principal(authentication)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();

        OAuth2AuthorizationSuccessHandler successHandler = (authorizedClient, principal, attributes) -> {
            authorizedClientRepository
                    .saveAuthorizedClient(
                            authorizedClient,
                            principal,
                            (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                            (HttpServletResponse) attributes.get(HttpServletResponse.class.getName())
                    );
        };

        authorizedClientManager.setAuthorizationSuccessHandler(successHandler);
        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);

        if (authorizedClient != null) {
            OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
            OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(authorizedClient.getClientRegistration(), authorizedClient.getAccessToken());
            OAuth2User oAuth2User = oAuth2UserService.loadUser(oAuth2UserRequest);

            SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
            authorityMapper.setPrefix("SYSTEM_");
            Set<GrantedAuthority> grantedAuthorities = authorityMapper.mapAuthorities(oAuth2User.getAuthorities());

            OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken(oAuth2User, grantedAuthorities, authorizedClient.getClientRegistration().getRegistrationId());

            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);
            model.addAttribute("oAuth2AuthenticationToken", oAuth2AuthenticationToken);
            model.addAttribute("accessToken", authorizedClient.getAccessToken().getTokenValue());
            model.addAttribute("refreshToken", authorizedClient.getRefreshToken().getTokenValue());
        }

        return "home";
    }

    @GetMapping("/oauth2Login/client-credentials-flow")
    public String oauth2Login(HttpServletRequest request, HttpServletResponse response, Model model) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("keycloak")
                .principal(authentication)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();

        OAuth2AuthorizationSuccessHandler successHandler = (authorizedClient, principal, attributes) -> {
            authorizedClientRepository
                    .saveAuthorizedClient(
                            authorizedClient,
                            principal,
                            (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                            (HttpServletResponse) attributes.get(HttpServletResponse.class.getName())
                    );
        };

        authorizedClientManager.setAuthorizationSuccessHandler(successHandler);
        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);
        model.addAttribute("oAuth2AuthenticationToken", authorizedClient);


        return "home";
    }

    @GetMapping("/oauth2Login/v2/password-flow")
    public String oauth2LoginV2PasswordFlow(@RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient authorizedClient,Model model) {

        if (authorizedClient != null) {
            OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
            OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(authorizedClient.getClientRegistration(), authorizedClient.getAccessToken());
            OAuth2User oAuth2User = oAuth2UserService.loadUser(oAuth2UserRequest);

            SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
            authorityMapper.setPrefix("SYSTEM_");
            Set<GrantedAuthority> grantedAuthorities = authorityMapper.mapAuthorities(oAuth2User.getAuthorities());

            OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken(oAuth2User, grantedAuthorities, authorizedClient.getClientRegistration().getRegistrationId());

            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);
            model.addAttribute("oAuth2AuthenticationToken", oAuth2AuthenticationToken);
            model.addAttribute("accessToken", authorizedClient.getAccessToken().getTokenValue());
            model.addAttribute("refreshToken", authorizedClient.getRefreshToken().getTokenValue());
        }

        return "home";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, authentication);
        return "index";
    }
}
