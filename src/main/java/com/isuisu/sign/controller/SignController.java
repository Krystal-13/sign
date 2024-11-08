package com.isuisu.sign.controller;

import com.isuisu.sign.dto.SignUpRequestDto;
import com.isuisu.sign.dto.SignUpResponseDto;
import com.isuisu.sign.service.SignService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class SignController {

    private final SignService signService;

    @PostMapping("/signup")
    public ResponseEntity<SignUpResponseDto> signup(
            @RequestBody @Valid SignUpRequestDto userDto
    ) {

        return ResponseEntity.ok(signService.signup(userDto));
    }
}
