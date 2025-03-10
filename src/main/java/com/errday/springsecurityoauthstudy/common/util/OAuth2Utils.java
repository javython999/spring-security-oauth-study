package com.errday.springsecurityoauthstudy.common.util;

import com.errday.springsecurityoauthstudy.model.Attributes;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

public class OAuth2Utils {

    public static Attributes getMainAttributes(OAuth2User oauth2User) {
        return Attributes.builder()
                .mainAttributes(oauth2User.getAttributes())
                .build();
    }

    public static Attributes getSubAttributes(OAuth2User oauth2User, String subAttributesKey) {
        return Attributes.builder()
                .subAttributes((Map<String, Object>) oauth2User.getAttributes().get(subAttributesKey))
                .build();
    }

    public static Attributes getOtherAttributes(OAuth2User oauth2User, String subAttributesKey, String otherAttributesKey) {
        Map<String, Object> subAttributes = (Map<String, Object>) oauth2User.getAttributes().get(subAttributesKey);
        return Attributes.builder()
                .otherAttributes((Map<String, Object>) subAttributes.get(otherAttributesKey))
                .build();
    }

}
