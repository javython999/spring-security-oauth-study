package com.errday.oauth2resourceserver.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.security.core.userdetails.User;

public class MacSecuritySigner extends SecuritySigner {

    @Override
    public String getJwt(User user, JWK jwk) throws JOSEException {

        MACSigner jwkSigner = null;
        try {
            jwkSigner = new MACSigner(((OctetSequenceKey) jwk).toOctetSequenceKey());
        } catch (KeyLengthException e) {
            throw new RuntimeException(e);
        }

        return super.getJwtInternal(jwkSigner, user, jwk);
    }
}
