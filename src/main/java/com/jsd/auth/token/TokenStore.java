package com.jsd.auth.token;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public interface TokenStore {

    String create(Token token);
    Optional<Token> read(String tokenStr);

    class Token {

        public final String username;
        public final Instant expiry;
        public final Map<String, String> attrs;

        public Token(String username, Instant expiry) {
            this.username = username;
            this.expiry = expiry;
            this.attrs = new ConcurrentHashMap<>();
        }

    }
}
