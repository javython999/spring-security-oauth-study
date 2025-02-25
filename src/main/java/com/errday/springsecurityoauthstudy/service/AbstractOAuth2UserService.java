package com.errday.springsecurityoauthstudy.service;

import com.errday.springsecurityoauthstudy.converters.ProviderUserConverter;
import com.errday.springsecurityoauthstudy.converters.ProviderUserRequest;
import com.errday.springsecurityoauthstudy.model.ProviderUser;
import com.errday.springsecurityoauthstudy.model.users.User;
import com.errday.springsecurityoauthstudy.repository.UserRepository;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.stereotype.Service;

@Service
@Getter
public class AbstractOAuth2UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private ProviderUserConverter<ProviderUserRequest, ProviderUser> providerUserConverter;

    protected ProviderUser providerUser(ProviderUserRequest providerUserRequest) {
        return providerUserConverter.convert(providerUserRequest);
    }

    public void register(ProviderUser providerUser, OAuth2UserRequest userRequest) {
        User findUser = userRepository.findByUsername(providerUser.getUsername());
        if (findUser == null) {
            userService.register(userRequest.getClientRegistration().getRegistrationId(), providerUser);
        }
    }
}
