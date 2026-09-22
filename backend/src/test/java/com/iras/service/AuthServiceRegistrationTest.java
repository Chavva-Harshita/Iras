package com.iras.service;

import com.iras.dto.auth.OtpSentResponse;
import com.iras.dto.auth.RegisterRequest;
import com.iras.entity.OtpPurpose;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService — registration flow")
class AuthServiceRegistrationTest {

    @Mock private UserRepository userRepository;
    @Mock private OtpService otpService;
    @Mock private RefreshTokenService refreshTokenService;

    private PasswordEncoder passwordEncoder;
    private JwtService jwtService;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        jwtService = new JwtService(
                "test_jwt_access_secret_key_that_is_at_least_32_characters",
                900_000L, 604_800_000L);
        authService = new AuthService(userRepository, passwordEncoder, jwtService, otpService, refreshTokenService);
    }

    @Test
    @DisplayName("Successful registration saves a new CUSTOMER user and initiates OTP")
    void register_newUser_savesAndInitiatesOtp() {
        RegisterRequest req = new RegisterRequest(
                "alice@example.com", "SecurePass1!", "Alice", "Smith", "9876543210");

        when(userRepository.findByEmailIgnoreCase("alice@example.com")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        when(otpService.generateAndSendOtp("alice@example.com", OtpPurpose.REGISTRATION))
                .thenReturn("123456");
        when(otpService.getExpirationMinutes()).thenReturn(10);

        OtpSentResponse response = authService.register(req);

        assertThat(response).isNotNull();
        assertThat(response.email()).isEqualTo("alice@example.com");
        assertThat(response.purpose()).isEqualTo("REGISTRATION");
        assertThat(response.devOtpCode()).isEqualTo("123456");

        // Verify user was saved with CUSTOMER role, not ADMIN
        verify(userRepository).save(argThat(user ->
                "CUSTOMER".equals(user.getRole()) &&
                !user.isVerified() &&
                !user.getPasswordHash().equals("SecurePass1!"))); // must be hashed
    }

    @Test
    @DisplayName("Email is stored in lower-case regardless of input case")
    void register_normalizeEmailToLowercase() {
        RegisterRequest req = new RegisterRequest(
                "Alice@EXAMPLE.COM", "SecurePass1!", "Alice", "Smith", null);

        when(userRepository.findByEmailIgnoreCase("alice@example.com")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        when(otpService.generateAndSendOtp(anyString(), any())).thenReturn("000000");
        when(otpService.getExpirationMinutes()).thenReturn(10);

        OtpSentResponse response = authService.register(req);

        assertThat(response.email()).isEqualTo("alice@example.com");
    }

    @Test
    @DisplayName("Duplicate email (verified account) throws AuthException")
    void register_duplicateVerifiedEmail_throwsAuthException() {
        User existing = buildVerifiedUser("bob@example.com");
        when(userRepository.findByEmailIgnoreCase("bob@example.com")).thenReturn(Optional.of(existing));

        RegisterRequest req = new RegisterRequest(
                "bob@example.com", "SecurePass1!", "Bob", "Brown", null);

        assertThatThrownBy(() -> authService.register(req))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("already exists");
    }

    @Test
    @DisplayName("Duplicate email (unverified) updates existing user and resends OTP")
    void register_duplicateUnverifiedEmail_updatesAndResends() {
        User existing = buildUnverifiedUser("carol@example.com");
        when(userRepository.findByEmailIgnoreCase("carol@example.com")).thenReturn(Optional.of(existing));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        when(otpService.generateAndSendOtp("carol@example.com", OtpPurpose.REGISTRATION))
                .thenReturn("654321");
        when(otpService.getExpirationMinutes()).thenReturn(10);

        RegisterRequest req = new RegisterRequest(
                "carol@example.com", "NewPass456!", "Carol", "White", null);

        OtpSentResponse response = authService.register(req);
        assertThat(response.email()).isEqualTo("carol@example.com");

        // Save called once (update), no new user created
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    @DisplayName("Password is hashed — stored hash does not equal raw password")
    void register_passwordIsHashed() {
        RegisterRequest req = new RegisterRequest(
                "dave@example.com", "MyRawPass99!", "Dave", "Jones", null);

        when(userRepository.findByEmailIgnoreCase("dave@example.com")).thenReturn(Optional.empty());
        when(otpService.generateAndSendOtp(anyString(), any())).thenReturn("111111");
        when(otpService.getExpirationMinutes()).thenReturn(10);

        User[] captured = new User[1];
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            captured[0] = inv.getArgument(0);
            return captured[0];
        });

        authService.register(req);

        assertThat(captured[0].getPasswordHash()).isNotEqualTo("MyRawPass99!");
        assertThat(passwordEncoder.matches("MyRawPass99!", captured[0].getPasswordHash())).isTrue();
    }

    @Test
    @DisplayName("Registration never sets role to ADMIN")
    void register_roleIsAlwaysCustomer() {
        RegisterRequest req = new RegisterRequest(
                "eve@example.com", "SecurePass1!", "Eve", "Adams", null);

        when(userRepository.findByEmailIgnoreCase("eve@example.com")).thenReturn(Optional.empty());
        when(otpService.generateAndSendOtp(anyString(), any())).thenReturn("222222");
        when(otpService.getExpirationMinutes()).thenReturn(10);

        User[] captured = new User[1];
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            captured[0] = inv.getArgument(0);
            return captured[0];
        });

        authService.register(req);
        assertThat(captured[0].getRole()).isEqualTo("CUSTOMER");
        assertThat(captured[0].getRole()).isNotEqualTo("ADMIN");
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private User buildVerifiedUser(String email) {
        User u = new User();
        u.setId(1L);
        u.setEmail(email);
        u.setPasswordHash("$2a$10$hash");
        u.setRole("CUSTOMER");
        u.setVerified(true);
        return u;
    }

    private User buildUnverifiedUser(String email) {
        User u = new User();
        u.setId(2L);
        u.setEmail(email);
        u.setPasswordHash("$2a$10$oldHash");
        u.setRole("CUSTOMER");
        u.setVerified(false);
        return u;
    }
}
