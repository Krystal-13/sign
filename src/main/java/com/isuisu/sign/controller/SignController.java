package com.isuisu.sign.controller;

import com.isuisu.sign.dto.SignInRequestDto;
import com.isuisu.sign.dto.SignInResponseDto;
import com.isuisu.sign.dto.SignUpRequestDto;
import com.isuisu.sign.dto.SignUpResponseDto;
import com.isuisu.sign.service.SignService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

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

    /**
     * JwtAuthenticationFilter 에서 로그인 진행 <p>
     * 해당 컨트롤러에서 실행되지 않습니다. Endpoint 만 만들어 둠.
     * @param userDto
     * @return SignInResponseDto
     */
    @PostMapping("/signin")
    public ResponseEntity<SignInResponseDto> signin(
            @RequestBody @Valid SignInRequestDto userDto
    ) {

        return ResponseEntity.ok(new SignInResponseDto("token"));
    }

    @GetMapping("/me")
    public ResponseEntity<String> whoami(Principal principal) {

        return ResponseEntity.ok(principal.getName());
    }
}
