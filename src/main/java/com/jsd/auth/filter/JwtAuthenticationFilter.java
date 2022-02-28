package com.jsd.auth.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.jsd.auth.provider.UsernamePasswordAuthentication;
import com.jsd.auth.token.TokenStore;
import static java.time.Instant.now;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private TokenStore tokenStore;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String tokenStr = request.getHeader("Authorization");
        
        String refreshStr = request.getHeader("Refresh");

        if(!tokenStr.isBlank()) {
            tokenStore.read(tokenStr).ifPresent(token -> {
                if(now().isBefore(token.expiry)) {
                    var auth = new UsernamePasswordAuthentication(token.username, null);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            });
        } else if(!refreshStr.isBlank()) {
            tokenStore.read(refreshStr).ifPresent(token -> {

            });
        }

        filterChain.doFilter(request, response);

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getServletPath().equals("/login");
    }
}

