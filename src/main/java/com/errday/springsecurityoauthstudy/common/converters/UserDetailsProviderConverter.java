package com.errday.springsecurityoauthstudy.common.converters;

import com.errday.springsecurityoauthstudy.model.FormUser;
import com.errday.springsecurityoauthstudy.model.ProviderUser;
import com.errday.springsecurityoauthstudy.model.users.User;

public class UserDetailsProviderConverter implements ProviderUserConverter<ProviderUserRequest, ProviderUser> {

    @Override
    public ProviderUser convert(ProviderUserRequest providerUserRequest) {
        if (providerUserRequest.user() == null) {
            return null;
        }

        User user = providerUserRequest.user();
        return FormUser.builder()
                .id(user.getId())
                .username(user.getUsername())
                .password(user.getPassword())
                .email(user.getEmail())
                .authorities(user.getAuthorities())
                .provider("none")
                .build();
    }
}
