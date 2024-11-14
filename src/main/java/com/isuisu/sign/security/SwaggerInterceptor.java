package com.isuisu.sign.security;

import com.isuisu.sign.model.UserRole;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
@Slf4j(topic = "SwaggerInterceptor")
public class SwaggerInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(
            HttpServletRequest request, HttpServletResponse response, Object handler
    ) throws Exception {
        String path = request.getRequestURI();
        log.info(path);
        // Swagger 경로에 대한 접근 제한을 위해 인증 여부 확인
        if (path.startsWith("/swagger-ui") || path.startsWith("/v2/api-docs")
                || path.startsWith("/swagger-resources")
        ) {

            Authentication authentication =
                    SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || !authentication.isAuthenticated()) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                        "Swagger access is restricted to authenticated users.");
                return false;
            }

            CustomUserDetails userDetails =
                    (CustomUserDetails) authentication.getPrincipal();

            // ROLE_SWAGGER 권한을 갖는 사용자만 접근 가능
            boolean hasSwaggerRole = userDetails.getAuthorities().stream()
                    .anyMatch(authority -> authority.getAuthority()
                            .equals(UserRole.ROLE_SWAGGER.name()));

            // 인증 정보가 없는 경우 접근 제한
            if (!hasSwaggerRole) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                        "Swagger access is restricted to authenticated users.");
                return false;
            }
        }

        return true;
    }
}
