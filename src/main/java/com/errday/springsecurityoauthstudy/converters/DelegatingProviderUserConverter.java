package com.errday.springsecurityoauthstudy.converters;

import com.errday.springsecurityoauthstudy.model.ProviderUser;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.List;
import java.util.Objects;

@Component
public class DelegatingProviderUserConverter implements ProviderUserConverter<ProviderUserRequest, ProviderUser> {

    List<ProviderUserConverter<ProviderUserRequest, ProviderUser>> converters;

    public DelegatingProviderUserConverter() {
        this.converters =
                List.of(
                        new OAuth2GoogleProviderUserConverter(),
                        new OAuth2NaverProviderUserConverter()
                );
    }


    @Override
    public ProviderUser convert(ProviderUserRequest providerUserRequest) {
        Assert.notNull(providerUserRequest, "providerUserRequest must not be null");
        return this.converters.stream()
                .map(converter -> converter.convert(providerUserRequest))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }
}
