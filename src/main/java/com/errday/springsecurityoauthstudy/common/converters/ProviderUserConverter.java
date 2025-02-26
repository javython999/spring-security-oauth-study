package com.errday.springsecurityoauthstudy.common.converters;

public interface ProviderUserConverter<T, R> {

    R convert(T t);
}
