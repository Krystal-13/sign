package com.isuisu.sign.mapper;

import com.isuisu.sign.dto.AuthorityDto;
import com.isuisu.sign.dto.SignUpResponseDto;
import com.isuisu.sign.model.User;
import com.isuisu.sign.model.UserRole;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

@Component
public class UserMapper {
    public SignUpResponseDto toSignUpResponseDto(User user) {
        return new SignUpResponseDto(
                user.getUsername(),
                user.getNickname(),
                toAuthorityDto(user.getAuthorities()));
    }

    private Set<AuthorityDto> toAuthorityDto(Set<UserRole> userRole) {
        return userRole.stream().map(
                role -> new AuthorityDto(role.name())).collect(Collectors.toSet());
    }
}
