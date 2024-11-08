package com.isuisu.sign.dto;

import java.util.Set;

public record SignUpResponseDto(
        String username,
        String nickname,
        Set<AuthorityDto> authorities
) {
}
