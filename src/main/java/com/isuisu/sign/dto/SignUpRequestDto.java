package com.isuisu.sign.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record SignUpRequestDto(
        @NotBlank(message = "아이디는 필수로 입력되어야 합니다.")
        @Size(min = 4, max = 20, message = "아이디는 4자 이상, 20자 이하로 입력해야 합니다.")
        String username,
        @NotBlank
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*[!@#$%^*+=\\-])(?=.*[0-9]).{8,}$",
                message = "비밀번호는 알파벳 대소문자(A~Z, a~z), 특수문자, 숫자(0~9), " +
                        "최소 8자 이상으로 이루어져 있어야 합니다.")
        String password,
        String nickname
) {
}
