package com.errday.springsecurityoauthstudy.service;

import com.errday.springsecurityoauthstudy.model.*;
import com.errday.springsecurityoauthstudy.repository.UserRepository;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Getter
public class AbstractOAuth2UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserService userService;

    protected ProviderUser providerUser(ClientRegistration clientRegistration, OAuth2User oAuth2User) {
        String registrationClientId = clientRegistration.getRegistrationId();

        if ("keycloak".equals(registrationClientId)) {
            return new KeyCloakUser(oAuth2User, clientRegistration);
        } else if ("google".equals(registrationClientId)) {
            return new GoogleUser(oAuth2User, clientRegistration);
        } else if ("naver".equals(registrationClientId)) {
            return new NaverUser(oAuth2User, clientRegistration);
        }

        return null;
    }

    public void register(ProviderUser providerUser, OAuth2UserRequest userRequest) {
        User findUser = userRepository.findByUsername(providerUser.getUsername());
        if (findUser == null) {
            userService.register(userRequest.getClientRegistration().getRegistrationId(), providerUser);
        }
    }
}
