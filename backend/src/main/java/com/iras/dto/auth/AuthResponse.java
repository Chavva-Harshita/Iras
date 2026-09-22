package com.iras.dto.auth;

public record AuthResponse(
        String accessToken,
        String tokenType,
        long expiresInMs,
        UserSummaryDto user
) {
    public static AuthResponse bearer(String accessToken, long expiresInMs, UserSummaryDto user) {
        return new AuthResponse(accessToken, "Bearer", expiresInMs, user);
    }
}
