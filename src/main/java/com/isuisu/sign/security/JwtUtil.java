package com.isuisu.sign.security;


import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Slf4j(topic = "JwtUtil")
@Component
public class JwtUtil {
    public static final String CLAIM_KEY_ROLES = "roles";
    public static final String CLAIM_KEY_USER_ID = "userId";
    public static final String BEARER_PREFIX = "Bearer ";

    @Value("${security.jwt.secret.key}")
    private String secretKey;

    @Value("${security.jwt.secret.expiration}")
    private long accessTokenTime;

    @Value("${security.jwt.refresh.expiration}")
    private long refreshTokenTime;

    private Key key;
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    @PostConstruct
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(secretKey);
        key = Keys.hmacShaKeyFor(bytes);
    }

    public long getRefreshTokenTime() {
        return refreshTokenTime;
    }

    public String createAccessToken(Long userId, String username, List<String> roles) {
        Instant now = Instant.now();

        return Jwts.builder()
                .setSubject(username)
                .claim(CLAIM_KEY_ROLES, roles)
                .claim(CLAIM_KEY_USER_ID, userId)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusMillis(accessTokenTime)))
                .signWith(key, signatureAlgorithm)
                .compact();
    }

    public String createRefreshToken(Long userId, String username, List<String> roles) {
        Instant now = Instant.now();

        return Jwts.builder()
                .setSubject(username)
                .claim(CLAIM_KEY_ROLES, roles)
                .claim(CLAIM_KEY_USER_ID, userId)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(
                        now.plus(Duration.ofSeconds(refreshTokenTime))))
                .signWith(key, signatureAlgorithm)
                .compact();
    }

    public String getJwtFromHeader(String bearerToken) {
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException |
                 SignatureException e) {
            throw new RuntimeException("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
        } catch (ExpiredJwtException e) {
            log.warn("Expired JWT token, 만료된 JWT token 입니다.");
            return false;
        } catch (UnsupportedJwtException e) {
            throw new RuntimeException("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
        }
    }

    public Claims getUserInfoFromToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody();
    }

}
