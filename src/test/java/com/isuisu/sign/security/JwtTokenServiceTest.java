package com.isuisu.sign.security;

import com.isuisu.sign.model.RefreshToken;
import com.isuisu.sign.repository.RefreshTokenRepository;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtTokenServiceTest {

    @InjectMocks
    private JwtTokenService jwtTokenService;
    @Mock
    private JwtUtil jwtUtil;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    private Long userId;
    private String username;
    private List<String> roles;
    private String accessToken;
    private String refreshToken;
    private String bearer;

    @BeforeEach
    void setUp() {
        this.userId = 1L;
        this.username = "testUser";
        this.roles = List.of("ROLE_USER");
        this.accessToken = "access-token";
        this.refreshToken = "refresh-token";
        this.bearer = "Bearer ";
    }

    @Test
    @DisplayName("로그인 성공 후 토큰 발급")
    void createToken() {

        when(jwtUtil.createAccessToken(userId, username, roles)).thenReturn(accessToken);
        when(jwtUtil.createRefreshToken(userId, username, roles)).thenReturn(refreshToken);

        Map<String, String> tokens = jwtTokenService.createToken(userId, username, roles);

        assertEquals("access-token", tokens.get("accessToken"));
        assertEquals("refresh-token", tokens.get("refreshToken"));
        verify(refreshTokenRepository).deleteByUserId(userId);
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("토큰 검증 성공")
    void validateTokenTrue() {
        when(jwtUtil.getJwtFromHeader(bearer + accessToken)).thenReturn(accessToken);
        when(jwtUtil.validateToken(accessToken)).thenReturn(true);

        String tokenValue = jwtTokenService.validateToken(bearer + accessToken);

        assertEquals(accessToken, tokenValue);
    }

    @Test
    @DisplayName("만료된 토큰은 null 반환")
    void validateTokenFalse() {
        when(jwtUtil.getJwtFromHeader(bearer + accessToken)).thenReturn(accessToken);
        when(jwtUtil.validateToken(accessToken)).thenReturn(false);

        String tokenValue = jwtTokenService.validateToken(bearer + accessToken);

        assertNull(tokenValue);
    }

    @Test
    @DisplayName("refreshToken 재발급")
    void renewAccessTokenWithRefreshToken() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("refreshToken", this.refreshToken));

        String refreshToken = jwtTokenService.getRefreshTokenFromCookies(request);

        assertEquals(this.refreshToken, refreshToken);
    }

    @Test
    @DisplayName("쿠키에서 refreshToken 추출")
    void getRefreshTokenFromCookies() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("refreshToken", this.refreshToken));

        String refreshToken = jwtTokenService.getRefreshTokenFromCookies(request);

        assertEquals(this.refreshToken, refreshToken);
    }

    @Test
    @DisplayName("refreshTokenCookie 생성")
    void createRefreshTokenCookie() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        jwtTokenService.createRefreshTokenCookie(response, refreshToken);

        Cookie cookie = response.getCookie(JwtTokenService.REFRESH_TOKEN_COOKIE_NAME);
        assertNotNull(cookie);
        assertEquals(refreshToken, cookie.getValue());
    }
}