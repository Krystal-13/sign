package com.isuisu.sign.security;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.isuisu.sign.security.JwtUtil.BEARER_PREFIX;

@Slf4j(topic = "JWT 검증 및 인가")
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    public static final String AUTHORIZATION_HEADER = "Authorization";
    private final JwtTokenService jwtTokenService;
    private final CustomUserDetailsService userDetailsService;

    public JwtAuthorizationFilter(
            JwtTokenService jwtTokenService, CustomUserDetailsService userDetailsService
    ) {
        this.jwtTokenService = jwtTokenService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain
    ) throws ServletException, IOException {

        log.info("로그인 후 토큰으로 검증");
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        String token = jwtTokenService.validateToken(bearerToken);

        // 만료된 JWT token 일 경우 -> 쿠키의 refreshToken 으로 새로운 토큰 발행
        if (token == null) {
            String refreshTokenFromCookies =
                    jwtTokenService.getRefreshTokenFromCookies(request);
            String username =
                    jwtTokenService.getUsernameFromToken(refreshTokenFromCookies);
            CustomUserDetails userDetails =
                    (CustomUserDetails) userDetailsService.loadUserByUsername(username);
            token = jwtTokenService.renewAccessTokenWithRefreshToken(
                        refreshTokenFromCookies, userDetails);

            response.setHeader(AUTHORIZATION_HEADER, BEARER_PREFIX + token);
        }

        String username = jwtTokenService.getUsernameFromToken(token);

        try {
            setAuthentication(username);
        } catch (Exception e) {
            log.error(e.getMessage());
            response.sendError(
                    HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed"
            );
            return;
        }

        filterChain.doFilter(request, response);
    }

    public void setAuthentication(String username) {

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        Authentication authentication = createAuthentication(username);
        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);
    }

    private Authentication createAuthentication(String username) {

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        return new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
    }
}
