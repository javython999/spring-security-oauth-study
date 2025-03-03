package com.errday.oauth2resourceserver.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import lombok.Setter;
import org.springframework.security.core.userdetails.User;

import java.security.PrivateKey;

@Setter
public class RsaPublicKeySecuritySigner extends SecuritySigner {

    private PrivateKey privateKey;

    @Override
    public String getJwt(User user, JWK jwk) throws JOSEException {

        RSASSASigner jwkSigner = new RSASSASigner(privateKey);
        return super.getJwtInternal(jwkSigner, user, jwk);
    }
}
