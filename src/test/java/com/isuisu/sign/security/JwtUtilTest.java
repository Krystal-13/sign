package com.isuisu.sign.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JwtUtilTest {

    @InjectMocks
    private JwtUtil jwtUtil;

    private final String secretKey = Base64.getEncoder().encodeToString(
            "this-is-a-very-strong-secret-key-123456".getBytes());
    private final long accessTokenTime = 300000; // 5 minute
    private final long refreshTokenTime = 3600000; // 1 hour

    private Long userId;
    private String username;
    private List<String> roles;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtUtil, "secretKey", secretKey);
        ReflectionTestUtils.setField(jwtUtil, "accessTokenTime", accessTokenTime);
        ReflectionTestUtils.setField(jwtUtil, "refreshTokenTime", refreshTokenTime);

        jwtUtil.init();

        this.userId = 1L;
        this.username = "testUser";
        this.roles = List.of("ROLE_USER");
    }

    @Test
    @DisplayName("AccessToken 발급")
    void createAccessToken() {
        String token = jwtUtil.createAccessToken(userId, username, roles);
        assertNotNull(token);

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(
                        Base64.getDecoder().decode(secretKey)))
                .build()
                .parseClaimsJws(token).getBody();

        assertEquals("testUser", claims.getSubject());
        assertEquals(1L, claims.get(JwtUtil.CLAIM_KEY_USER_ID, Long.class));
        assertEquals(Arrays.asList("ROLE_USER"), claims.get(JwtUtil.CLAIM_KEY_ROLES));
        assertEquals(accessTokenTime,
                (claims.getExpiration().getTime())
                        - (claims.getIssuedAt().getTime()));
    }

    @Test
    @DisplayName("RefreshToken 발급")
    void createRefreshToken() {
        String token = jwtUtil.createRefreshToken(userId, username, roles);
        assertNotNull(token);

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(
                        Base64.getDecoder().decode(secretKey)))
                .build()
                .parseClaimsJws(token).getBody();

        assertEquals("testUser", claims.getSubject());
        assertEquals(1L, claims.get(JwtUtil.CLAIM_KEY_USER_ID, Long.class));
        assertEquals(Arrays.asList("ROLE_USER"), claims.get(JwtUtil.CLAIM_KEY_ROLES));
        assertEquals(refreshTokenTime,
                ((claims.getExpiration().getTime())
                        - (claims.getIssuedAt().getTime())) / 1000);
    }

    @Test
    @DisplayName("만료된 토큰")
    void validateTokenFalse() throws InterruptedException {
        ReflectionTestUtils.setField(jwtUtil, "accessTokenTime", 1L);
        jwtUtil.init();

        String expiredToken = jwtUtil.createAccessToken(userId, username, roles);

        Thread.sleep(2); // 2밀리초 대기하여 토큰이 만료되도록 함

        assertFalse(jwtUtil.validateToken(expiredToken));
    }

    @Test
    @DisplayName("토큰에서 사용자정보 추출")
    void getUserInfoFromToken() {
        String token = jwtUtil.createAccessToken(userId, username, roles);
        Claims claims = jwtUtil.getUserInfoFromToken(token);

        assertNotNull(claims);
        assertEquals("testUser", claims.getSubject());
        assertEquals(1L, claims.get(JwtUtil.CLAIM_KEY_USER_ID, Long.class));
        assertEquals(List.of("ROLE_USER"), claims.get(JwtUtil.CLAIM_KEY_ROLES));
    }
}