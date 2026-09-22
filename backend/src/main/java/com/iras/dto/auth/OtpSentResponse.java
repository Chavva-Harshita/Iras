package com.iras.dto.auth;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record OtpSentResponse(
        String message,
        String email,
        String purpose,
        int expiresInMinutes,
        String devOtpCode
) {}
