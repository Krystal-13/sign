package com.isuisu.sign.service;

import com.isuisu.sign.dto.AuthorityDto;
import com.isuisu.sign.dto.SignUpRequestDto;
import com.isuisu.sign.dto.SignUpResponseDto;
import com.isuisu.sign.mapper.UserMapper;
import com.isuisu.sign.model.User;
import com.isuisu.sign.model.UserRole;
import com.isuisu.sign.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SignServiceTest {

    @InjectMocks
    private SignService signService;

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private UserMapper userMapper;

    private String username;
    private String password;
    private String nickname;

    @BeforeEach
    void setUp() {
        this.username = "testUser";
        this.password = "testPassword";
        this.nickname = "testNickname";
    }
    @Test
    @DisplayName("회원가입 성공")
    void signupSuccess() {
        Set<UserRole> roles = Set.of(UserRole.ROLE_USER);
        AuthorityDto authorityDto = new AuthorityDto(UserRole.ROLE_USER.name());

        SignUpRequestDto signUpRequestDto = new SignUpRequestDto(username, password, nickname);

        when(userRepository.existsByUsername(username)).thenReturn(false);
        when(passwordEncoder.encode(signUpRequestDto.password())).thenReturn("encodedPassword");
        User user = new User(username, password, nickname, roles);
        when(userRepository.save(any(User.class))).thenReturn(user);
        when(userMapper.toSignUpResponseDto(any(User.class))).thenReturn(new SignUpResponseDto(username, nickname, Set.of(authorityDto)));

        // when
        SignUpResponseDto response = signService.signup(signUpRequestDto);

        // then
        assertNotNull(response);
        assertEquals("testUser", response.username());
        assertEquals("testNickname", response.nickname());
    }

    @Test
    @DisplayName("회원가입 실패 - 중복 아이디")
    void signupFail() {
        SignUpRequestDto signUpRequestDto = new SignUpRequestDto(username, password, nickname);

        when(userRepository.existsByUsername(signUpRequestDto.username())).thenReturn(true);

        // when & then
        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> signService.signup(signUpRequestDto)
        );

        assertEquals("400 BAD_REQUEST \"중복된 아이디가 존재합니다.\"", exception.getMessage());
    }
}