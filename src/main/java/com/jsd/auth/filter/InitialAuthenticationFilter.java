package com.jsd.auth.filter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jsd.auth.provider.UsernamePasswordAuthentication;
import com.jsd.auth.token.TokenStore;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.time.temporal.ChronoUnit;
import static java.time.Instant.now;

@Component
public class InitialAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private AuthenticationManager manager;

    @Value("${jwt.expiry.minutes}")
    private int expiryMinutes;

    @Value("${jwt.refresh.expiry.minutes}")
    private int refreshExpiryMinutes;

    @Autowired
    private TokenStore tokenStore;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {
        String username = request.getHeader("username");
        String password = request.getHeader("password");

        Authentication a = new UsernamePasswordAuthentication(username, password);
        var authen = manager.authenticate(a);

        var expiry = now().plus(expiryMinutes, ChronoUnit.MINUTES);
        var token = new TokenStore.Token(username, expiry);

        var tokenStr = tokenStore.create(token);
        response.setHeader("Authorization", tokenStr);
        response.setHeader("Content-Type", "text/plain"); 

        try {
            var writer = response.getWriter();
            writer.write(tokenStr);
            writer.close();

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getServletPath().equals("/login");
    }
}
