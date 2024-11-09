package com.isuisu.sign.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.isuisu.sign.dto.SignInRequestDto;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Slf4j(topic = "로그인 및 JWT 생성")
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final JwtTokenService jwtTokenService;

    public JwtAuthenticationFilter(JwtTokenService jwtTokenService) {
        this.jwtTokenService = jwtTokenService;
        setFilterProcessesUrl("/api/signin");
    }

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request, HttpServletResponse response
    ) throws AuthenticationException {

        log.info("로그인 시도");
        try {
            SignInRequestDto userDto = new ObjectMapper().readValue(
                    request.getInputStream(), SignInRequestDto.class
            );

            // 1. UsernamePasswordAuthenticationToken 생성
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(
                            userDto.username(),
                            userDto.password()
                    );

            // 2. AuthenticationManager에 인증 요청 -> 3. AuthenticationProvider를 사용
            return getAuthenticationManager().authenticate(authenticationToken);

        } catch (IOException e) {
            log.error(e.getMessage());
            throw new RuntimeException(e.getMessage());
        }
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request, HttpServletResponse response,
            FilterChain chain, Authentication authResult
    ) {

        CustomUserDetails userDetails = (CustomUserDetails) authResult.getPrincipal();

        List<String> roles = authResult.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        Map<String, String> tokenMap = jwtTokenService.createToken(
                userDetails.getUserId(), userDetails.getUsername(), roles
        );

        try {
            writeTokenResponse(response,
                    tokenMap.get("accessToken"), tokenMap.get("refreshToken"));
        } catch (IOException e) {
            log.error(e.getMessage());
            throw new RuntimeException(e.getMessage());
        }
    }

    @Override
    protected void unsuccessfulAuthentication(
            HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed
    ) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private void writeTokenResponse(
            HttpServletResponse response, String accessToken, String refreshToken
    ) throws IOException {

        String jsonResponse = String.format("{\"token\": \"%s\"}", accessToken);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(jsonResponse);

        jwtTokenService.createRefreshTokenCookie(response, refreshToken);
    }
}
