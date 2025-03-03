package com.errday.oauth2resourceserver.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.security.core.userdetails.User;

public class RsaSecuritySigner extends SecuritySigner {

    @Override
    public String getJwt(User user, JWK jwk) throws JOSEException {

        RSASSASigner jwkSigner = null;
        try {
            jwkSigner = new RSASSASigner(((RSAKey) jwk).toRSAPrivateKey());
        } catch (KeyLengthException e) {
            throw new RuntimeException(e);
        }

        return super.getJwtInternal(jwkSigner, user, jwk);
    }
}
