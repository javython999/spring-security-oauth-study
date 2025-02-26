package com.errday.springsecurityoauthstudy.common.converters;

import com.errday.springsecurityoauthstudy.common.enums.OAuth2Config;
import com.errday.springsecurityoauthstudy.common.util.OAuth2Utils;
import com.errday.springsecurityoauthstudy.model.ProviderUser;
import com.errday.springsecurityoauthstudy.model.social.KakaoOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public class OAuth2KakaoOidcProviderUserConverter implements ProviderUserConverter<ProviderUserRequest, ProviderUser> {

    @Override
    public ProviderUser convert(ProviderUserRequest providerUserRequest) {
        if (!OAuth2Config.SocialType.NAVER.getSocialName().equals(providerUserRequest.clientRegistration().getRegistrationId())) {
            return null;
        }

        if (!(providerUserRequest.oAuth2User() instanceof OidcUser)) {
            return null;
        }

        return new KakaoOidcUser(
                OAuth2Utils.getMainAttributes(providerUserRequest.oAuth2User()),
                providerUserRequest.oAuth2User(),
                providerUserRequest.clientRegistration()
        );
    }
}
