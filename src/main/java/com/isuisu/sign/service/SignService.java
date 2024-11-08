package com.isuisu.sign.service;

import com.isuisu.sign.dto.SignUpRequestDto;
import com.isuisu.sign.dto.SignUpResponseDto;
import com.isuisu.sign.mapper.UserMapper;
import com.isuisu.sign.model.User;
import com.isuisu.sign.model.UserRole;
import com.isuisu.sign.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class SignService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    @Transactional
    public SignUpResponseDto signup(SignUpRequestDto signUpRequestDto) {

        if (userRepository.existsByUsername(signUpRequestDto.username())) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "중복된 아이디가 존재합니다.");
        }

        User user = User.signUp(
                signUpRequestDto.username(),
                passwordEncoder.encode(signUpRequestDto.password()),
                signUpRequestDto.nickname(),
                Collections.singleton(UserRole.ROLE_USER)
        );
        userRepository.save(user);

        return userMapper.toSignUpResponseDto(user);
    }
}
