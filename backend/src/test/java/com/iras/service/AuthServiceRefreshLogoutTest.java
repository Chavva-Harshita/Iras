package com.iras.service;

import com.iras.dto.auth.AuthResponse;
import com.iras.dto.auth.LoginRequest;
import com.iras.entity.RefreshToken;
import com.iras.entity.User;
import com.iras.exception.TokenRefreshException;
import com.iras.repository.RefreshTokenRepository;
import com.iras.repository.UserRepository;
import com.iras.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService — refresh and logout flow")
class AuthServiceRefreshLogoutTest {

    @Mock private UserRepository userRepository;
    @Mock private OtpService otpService;
    @Mock private RefreshTokenRepository refreshTokenRepository;

    private PasswordEncoder passwordEncoder;
    private JwtService jwtService;
    private RefreshTokenService refreshTokenService;
    private AuthService authService;

    private static final String RAW_PASSWORD = "ValidPass99!";

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        jwtService = new JwtService(
                "test_jwt_access_secret_key_that_is_at_least_32_characters",
                900_000L, 604_800_000L);
        refreshTokenService = new RefreshTokenService(refreshTokenRepository, jwtService);
        authService = new AuthService(userRepository, passwordEncoder, jwtService, otpService, refreshTokenService);
    }

    @Test
    @DisplayName("refreshToken rotates token and issues new access token")
    void refreshToken_success_rotatesAndIssuesNewTokens() {
        User user = buildVerifiedUser("alice@example.com");
        String oldRaw  = jwtService.generateRefreshTokenString();
        String oldHash = jwtService.hashToken(oldRaw);
        RefreshToken oldToken = buildActiveToken(user, oldHash);

        when(refreshTokenRepository.findByTokenHash(oldHash)).thenReturn(Optional.of(oldToken));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        AuthService.LoginResult result = authService.refreshToken(oldRaw);

        assertThat(result.rawRefreshToken()).isNotBlank();
        assertThat(result.rawRefreshToken()).isNotEqualTo(oldRaw); // rotated
        assertThat(result.response().accessToken()).isNotBlank();
        assertThat(jwtService.isAccessTokenValid(result.response().accessToken())).isTrue();
    }

    @Test
    @DisplayName("refreshToken with revoked token detects replay and throws")
    void refreshToken_revokedToken_throwsTokenRefreshException() {
        User user = buildVerifiedUser("alice@example.com");
        String rawToken = jwtService.generateRefreshTokenString();
        String tokenHash = jwtService.hashToken(rawToken);
        RefreshToken revokedToken = buildRevokedToken(user, tokenHash);

        when(refreshTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(revokedToken));

        assertThatThrownBy(() -> authService.refreshToken(rawToken))
                .isInstanceOf(TokenRefreshException.class)
                .hasMessageContaining("reuse detected");

        verify(refreshTokenRepository).revokeAllByUserId(eq(user.getId()), any(Instant.class));
    }

    @Test
    @DisplayName("refreshToken with expired token throws TokenRefreshException")
    void refreshToken_expiredToken_throws() {
        User user = buildVerifiedUser("alice@example.com");
        String rawToken  = jwtService.generateRefreshTokenString();
        String tokenHash = jwtService.hashToken(rawToken);
        RefreshToken expired = buildExpiredToken(user, tokenHash);

        when(refreshTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(expired));

        assertThatThrownBy(() -> authService.refreshToken(rawToken))
                .isInstanceOf(TokenRefreshException.class)
                .hasMessageContaining("expired");
    }

    @Test
    @DisplayName("logout revokes the refresh token in database")
    void logout_revokesRefreshToken() {
        User user = buildVerifiedUser("alice@example.com");
        String rawToken  = jwtService.generateRefreshTokenString();
        String tokenHash = jwtService.hashToken(rawToken);
        RefreshToken activeToken = buildActiveToken(user, tokenHash);

        when(refreshTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(activeToken));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        authService.logout(rawToken);

        assertThat(activeToken.isRevoked()).isTrue();
        assertThat(activeToken.getRevokedAt()).isNotNull();
    }

    @Test
    @DisplayName("logout with null/blank token does not throw")
    void logout_nullToken_doesNotThrow() {
        assertThatCode(() -> authService.logout(null)).doesNotThrowAnyException();
        assertThatCode(() -> authService.logout("  ")).doesNotThrowAnyException();
        verify(refreshTokenRepository, never()).findByTokenHash(any());
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private User buildVerifiedUser(String email) {
        User u = new User();
        u.setId(1L);
        u.setEmail(email);
        u.setPasswordHash(passwordEncoder.encode(RAW_PASSWORD));
        u.setRole("CUSTOMER");
        u.setVerified(true);
        u.setCreatedAt(Instant.now());
        u.setUpdatedAt(Instant.now());
        return u;
    }

    private RefreshToken buildActiveToken(User user, String hash) {
        return new RefreshToken(user, hash, Instant.now().plus(7, ChronoUnit.DAYS));
    }

    private RefreshToken buildRevokedToken(User user, String hash) {
        RefreshToken t = buildActiveToken(user, hash);
        t.setRevoked(true);
        t.setRevokedAt(Instant.now().minus(1, ChronoUnit.HOURS));
        return t;
    }

    private RefreshToken buildExpiredToken(User user, String hash) {
        return new RefreshToken(user, hash, Instant.now().minus(1, ChronoUnit.HOURS));
    }
}
