package com.isuisu.sign.security;

import com.isuisu.sign.model.RefreshToken;
import com.isuisu.sign.repository.RefreshTokenRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j(topic = "JwtTokenService")
public class JwtTokenService {
    public static final String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";

    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    public Map<String, String> createToken(
            Long userId, String username, List<String> roles
    ) {

        String accessToken = jwtUtil.createAccessToken(userId, username, roles);
        String refreshToken = jwtUtil.createRefreshToken(userId, username, roles);

        refreshTokenRepository.deleteByUserId(userId);
        refreshTokenRepository.save(new RefreshToken(userId, refreshToken));

        return Map.of("accessToken", accessToken, "refreshToken", refreshToken);
    }

    public String validateToken(String bearerToken) {

        String tokenValue = jwtUtil.getJwtFromHeader(bearerToken);

        if (!StringUtils.hasText(tokenValue)) {
            throw new RuntimeException("토큰이 비어 있습니다. 유효하지 않은 Access Token입니다.");
        }

        if (!jwtUtil.validateToken(tokenValue)) {
            log.warn("Expired JWT token, 만료된 JWT token 입니다.");
            return null;
        }

        return tokenValue;
    }

    public String renewAccessTokenWithRefreshToken(
            String refreshToken, CustomUserDetails userDetails
    ) {

        if (!jwtUtil.validateToken(refreshToken)) {
            throw new RuntimeException("만료되었거나 유효하지 않은 Refresh Token입니다.");
        }

        if (!refreshTokenRepository.existsByRefreshToken(refreshToken)) {
            throw new RuntimeException("데이터베이스에 존재하지 않는 Refresh Token입니다.");
        }

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return jwtUtil.createAccessToken(
                userDetails.getUserId(), userDetails.getUsername(), roles);
    }

    public String getRefreshTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (REFRESH_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    public void createRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshTokenCookie = new Cookie(REFRESH_TOKEN_COOKIE_NAME, refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge((int) jwtUtil.getRefreshTokenTime());
        response.addCookie(refreshTokenCookie);
    }

    public String getUsernameFromToken(String token) {

        return jwtUtil.getUserInfoFromToken(token).getSubject();
    }
}
