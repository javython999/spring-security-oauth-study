package com.errday.springsecurityoauthstudy.converters;

import com.errday.springsecurityoauthstudy.converters.enums.OAuth2Config;
import com.errday.springsecurityoauthstudy.model.ProviderUser;
import com.errday.springsecurityoauthstudy.model.social.GoogleUser;
import com.errday.springsecurityoauthstudy.util.OAuth2Util;

public class OAuth2GoogleProviderUserConverter implements ProviderUserConverter<ProviderUserRequest, ProviderUser> {

    @Override
    public ProviderUser convert(ProviderUserRequest providerUserRequest) {

        if (!OAuth2Config.SocialType.GOOGLE.getSocialName().equals(providerUserRequest.clientRegistration().getRegistrationId())) {
            return null;
        }

        return new GoogleUser(
                OAuth2Util.getMainAttributes(providerUserRequest.oAuth2User()),
                providerUserRequest.oAuth2User(),
                providerUserRequest.clientRegistration()
        );
    }
}
