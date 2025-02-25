package com.errday.springsecurityoauthstudy.converters;

import com.errday.springsecurityoauthstudy.converters.enums.OAuth2Config;
import com.errday.springsecurityoauthstudy.model.ProviderUser;
import com.errday.springsecurityoauthstudy.model.social.NaverUser;
import com.errday.springsecurityoauthstudy.util.OAuth2Util;

public class OAuth2NaverProviderUserConverter implements ProviderUserConverter<ProviderUserRequest, ProviderUser> {

    @Override
    public ProviderUser convert(ProviderUserRequest providerUserRequest) {
        if (!OAuth2Config.SocialType.NAVER.getSocialName().equals(providerUserRequest.clientRegistration().getRegistrationId())) {
            return null;
        }

        return new NaverUser(
                OAuth2Util.getSubAttributes(providerUserRequest.oAuth2User(), "response"),
                providerUserRequest.oAuth2User(),
                providerUserRequest.clientRegistration()
        );
    }
}
