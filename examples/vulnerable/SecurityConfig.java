package com.example.vuln;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
public class SecurityConfig {

    private static final String JWT_SECRET = "my-jwt-signing-secret-key-2024";

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        return http.build();
    }

    public String issueToken(String subject) {
        return Jwts.builder()
                .setSubject(subject)
                .signWith(SignatureAlgorithm.HS256, "hardcoded-hmac-secret")
                .compact();
    }

    public ObjectMapper mapper() {
        ObjectMapper om = new ObjectMapper();
        om.enableDefaultTyping();
        return om;
    }
}
