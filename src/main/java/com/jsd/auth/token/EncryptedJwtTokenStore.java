package com.jsd.auth.token;

import java.util.Date;
import java.util.Optional;

import javax.crypto.SecretKey;

import com.nimbusds.jwt.JWTClaimsSet;

public class EncryptedJwtTokenStore implements TokenStore {
    private final SecretKey encKey;

    public EncryptedJwtTokenStore(SecretKey encKey) {
        this.encKey = encKey;
    }

    @Override
    public String create(Token token) {
        
        var claimSet = new JWTClaimsSet.Builder()
            .subject(token.username)
            .expirationTime(Date.from(token.expiry))
            .claim("attrs", token.attrs)
            .build();
       

        return null;
    }

    @Override
    public Optional<Token> read(String tokenStr) {
        return Optional.empty();
    } 
}
