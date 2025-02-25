package com.errday.springsecurityoauthstudy.converters;

public interface ProviderUserConverter<T, R> {

    R convert(T t);
}
