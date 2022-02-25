package com.jsd.auth.token;

import java.util.Date;
import java.util.Optional;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.beans.factory.annotation.Value;

public class JwtTokenStoreImpl implements TokenStore {

    private final String signingKey;

    public JwtTokenStoreImpl(String signingKey) {
        this.signingKey = signingKey;
    }

    @Override
    public String create(Token token) {
        
        var claimSet = new JWTClaimsSet.Builder()
            .subject(token.username)
            .expirationTime(Date.from(token.expiry))
            .claim("attrs", token.attrs)
            .build();

        var header = new JWSHeader(JWSAlgorithm.HS256);
        var jwt = new SignedJWT(header, claimSet);

        byte[] secret = signingKey.getBytes();

        try {
            JWSSigner signer = new MACSigner(secret);
            jwt.sign(signer);

            return jwt.serialize();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    @Override
    public Optional<Token> Read(String tokenStr) {
        return Optional.empty();
    }
    
}
