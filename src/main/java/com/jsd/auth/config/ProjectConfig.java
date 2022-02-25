package com.jsd.auth.config;

import com.jsd.auth.token.JwtTokenStoreImpl;
import com.jsd.auth.token.TokenStore;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ProjectConfig {

    @Value("${jwt.signing.key}")
    private String signingKey;
    
    @Bean
    public TokenStore tokenStore() {
        var a = new JwtTokenStoreImpl(signingKey);

        return a;
    }

}
