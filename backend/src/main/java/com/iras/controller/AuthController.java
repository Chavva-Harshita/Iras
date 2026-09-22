package com.iras.controller;

import com.iras.dto.auth.AuthResponse;
import com.iras.dto.auth.LoginRequest;
import com.iras.dto.auth.MessageResponse;
import com.iras.dto.auth.OtpSentResponse;
import com.iras.dto.auth.RegisterRequest;
import com.iras.dto.auth.ResendOtpRequest;
import com.iras.dto.auth.UserSummaryDto;
import com.iras.dto.auth.VerifyOtpRequest;
import com.iras.exception.AuthException;
import com.iras.security.SecurityUtils;
import com.iras.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    public static final String REFRESH_COOKIE_NAME = "iras_refresh_token";

    private final AuthService authService;
    private final boolean cookieSecure;
    private final long refreshExpirationMs;

    public AuthController(
            AuthService authService,
            @Value("${iras.security.cookie-secure:false}") boolean cookieSecure,
            @Value("${iras.jwt.refresh-expiration-ms:604800000}") long refreshExpirationMs) {
        this.authService = authService;
        this.cookieSecure = cookieSecure;
        this.refreshExpirationMs = refreshExpirationMs;
    }

    @PostMapping("/register")
    public ResponseEntity<OtpSentResponse> register(@Valid @RequestBody RegisterRequest request) {
        OtpSentResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<MessageResponse> verifyOtp(@Valid @RequestBody VerifyOtpRequest request) {
        MessageResponse response = authService.verifyOtp(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<OtpSentResponse> resendOtp(@Valid @RequestBody ResendOtpRequest request) {
        OtpSentResponse response = authService.resendOtp(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse response) {
        AuthService.LoginResult result = authService.login(request);
        setRefreshTokenCookie(response, result.rawRefreshToken(), Duration.ofMillis(refreshExpirationMs));
        return ResponseEntity.ok(result.response());
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            @CookieValue(name = REFRESH_COOKIE_NAME, required = false) String refreshToken,
            HttpServletResponse response) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new AuthException("Refresh token cookie is missing.");
        }
        AuthService.LoginResult result = authService.refreshToken(refreshToken);
        setRefreshTokenCookie(response, result.rawRefreshToken(), Duration.ofMillis(refreshExpirationMs));
        return ResponseEntity.ok(result.response());
    }

    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(
            @CookieValue(name = REFRESH_COOKIE_NAME, required = false) String refreshToken,
            HttpServletResponse response) {
        if (refreshToken != null && !refreshToken.isBlank()) {
            authService.logout(refreshToken);
        }
        clearRefreshTokenCookie(response);
        return ResponseEntity.ok(new MessageResponse("Successfully logged out."));
    }

    @GetMapping("/me")
    public ResponseEntity<UserSummaryDto> getCurrentUser() {
        Long userId = SecurityUtils.getCurrentUserId()
                .orElseThrow(() -> new AuthException("Not authenticated."));
        UserSummaryDto user = authService.getCurrentUser(userId);
        return ResponseEntity.ok(user);
    }

    private void setRefreshTokenCookie(HttpServletResponse response, String token, Duration maxAge) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE_NAME, token)
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/api/auth")
                .maxAge(maxAge)
                .sameSite("Lax")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private void clearRefreshTokenCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/api/auth")
                .maxAge(Duration.ZERO)
                .sameSite("Lax")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
