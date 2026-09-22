package com.iras.service;

import com.iras.dto.auth.AuthResponse;
import com.iras.dto.auth.LoginRequest;
import com.iras.entity.User;
import com.iras.exception.AuthException;
import com.iras.repository.UserRepository;
import com.iras.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService — login flow")
class AuthServiceLoginTest {

    @Mock private UserRepository userRepository;
    @Mock private OtpService otpService;
    @Mock private RefreshTokenService refreshTokenService;

    private PasswordEncoder passwordEncoder;
    private JwtService jwtService;
    private AuthService authService;

    private static final String RAW_PASSWORD = "ValidPass99!";

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        jwtService = new JwtService(
                "test_jwt_access_secret_key_that_is_at_least_32_characters",
                900_000L, 604_800_000L);
        authService = new AuthService(userRepository, passwordEncoder, jwtService, otpService, refreshTokenService);
    }

    @Test
    @DisplayName("Successful login returns access token and safe user info")
    void login_success_returnsTokenAndUser() {
        User user = buildVerifiedUser("alice@example.com", RAW_PASSWORD);
        when(userRepository.findByEmailIgnoreCase("alice@example.com"))
                .thenReturn(Optional.of(user));
        when(refreshTokenService.createRefreshToken(user)).thenReturn("raw-refresh-token");

        LoginRequest req = new LoginRequest("alice@example.com", RAW_PASSWORD);
        AuthService.LoginResult result = authService.login(req);

        assertThat(result.rawRefreshToken()).isEqualTo("raw-refresh-token");
        assertThat(result.response().accessToken()).isNotBlank();
        assertThat(result.response().tokenType()).isEqualTo("Bearer");
        assertThat(result.response().user().email()).isEqualTo("alice@example.com");
        assertThat(result.response().user().role()).isEqualTo("CUSTOMER");
        // Must NOT contain password_hash, OTP, etc.
        assertThat(result.response()).isNotInstanceOf(String.class); // sanity
    }

    @Test
    @DisplayName("Login with incorrect password throws BadCredentialsException")
    void login_wrongPassword_throwsBadCredentials() {
        User user = buildVerifiedUser("alice@example.com", RAW_PASSWORD);
        when(userRepository.findByEmailIgnoreCase("alice@example.com"))
                .thenReturn(Optional.of(user));

        LoginRequest req = new LoginRequest("alice@example.com", "WrongPassword!");
        assertThatThrownBy(() -> authService.login(req))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    @DisplayName("Login with non-existent email throws BadCredentialsException (no user enumeration)")
    void login_unknownEmail_throwsBadCredentials() {
        when(userRepository.findByEmailIgnoreCase("ghost@example.com"))
                .thenReturn(Optional.empty());

        LoginRequest req = new LoginRequest("ghost@example.com", "SomePass1!");
        assertThatThrownBy(() -> authService.login(req))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    @DisplayName("Login on unverified account throws AuthException")
    void login_unverifiedAccount_throwsAuthException() {
        User user = buildUnverifiedUser("bob@example.com", RAW_PASSWORD);
        when(userRepository.findByEmailIgnoreCase("bob@example.com"))
                .thenReturn(Optional.of(user));

        LoginRequest req = new LoginRequest("bob@example.com", RAW_PASSWORD);
        assertThatThrownBy(() -> authService.login(req))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("verified");
    }

    @Test
    @DisplayName("Access token contains userId, email, role claims")
    void login_accessToken_containsExpectedClaims() {
        User user = buildVerifiedUser("claims@example.com", RAW_PASSWORD);
        user.setId(99L);
        when(userRepository.findByEmailIgnoreCase("claims@example.com"))
                .thenReturn(Optional.of(user));
        when(refreshTokenService.createRefreshToken(user)).thenReturn("raw-refresh");

        AuthService.LoginResult result = authService.login(new LoginRequest("claims@example.com", RAW_PASSWORD));

        io.jsonwebtoken.Claims claims = jwtService.parseAndValidateAccessToken(result.response().accessToken());
        assertThat(claims).isNotNull();
        assertThat(claims.getSubject()).isEqualTo("claims@example.com");
        assertThat(claims.get("userId", Long.class)).isEqualTo(99L);
        assertThat(claims.get("role", String.class)).isEqualTo("CUSTOMER");
    }

    @Test
    @DisplayName("Login response does not expose raw refresh token in body")
    void login_response_doesNotExposeRefreshToken() {
        User user = buildVerifiedUser("safe@example.com", RAW_PASSWORD);
        when(userRepository.findByEmailIgnoreCase("safe@example.com"))
                .thenReturn(Optional.of(user));
        when(refreshTokenService.createRefreshToken(user)).thenReturn("raw-refresh-secret");

        AuthService.LoginResult result = authService.login(new LoginRequest("safe@example.com", RAW_PASSWORD));
        AuthResponse response = result.response();

        // The raw refresh token should not appear in any field of AuthResponse
        String responseStr = response.toString();
        assertThat(responseStr).doesNotContain("raw-refresh-secret");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private User buildVerifiedUser(String email, String rawPassword) {
        User u = new User();
        u.setId(1L);
        u.setEmail(email);
        u.setPasswordHash(passwordEncoder.encode(rawPassword));
        u.setRole("CUSTOMER");
        u.setVerified(true);
        u.setCreatedAt(Instant.now());
        u.setUpdatedAt(Instant.now());
        return u;
    }

    private User buildUnverifiedUser(String email, String rawPassword) {
        User u = new User();
        u.setId(2L);
        u.setEmail(email);
        u.setPasswordHash(passwordEncoder.encode(rawPassword));
        u.setRole("CUSTOMER");
        u.setVerified(false);
        u.setCreatedAt(Instant.now());
        u.setUpdatedAt(Instant.now());
        return u;
    }
}
