package com.iras.service;

import com.iras.dto.auth.MessageResponse;
import com.iras.dto.auth.VerifyOtpRequest;
import com.iras.entity.OtpPurpose;
import com.iras.entity.OtpVerification;
import com.iras.entity.User;
import com.iras.exception.AuthException;
import com.iras.exception.OtpException;
import com.iras.repository.OtpVerificationRepository;
import com.iras.repository.UserRepository;
import com.iras.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService — OTP verification flow")
class AuthServiceOtpVerificationTest {

    @Mock private UserRepository userRepository;
    @Mock private OtpVerificationRepository otpRepository;
    @Mock private OtpNotificationService notificationService;
    @Mock private RefreshTokenService refreshTokenService;

    private OtpService otpService;
    private AuthService authService;

    private static final String EMAIL           = "verify@example.com";
    private static final int    EXPIRATION_MINS = 10;
    private static final int    MAX_ATTEMPTS    = 5;

    @BeforeEach
    void setUp() {
        otpService = new OtpService(otpRepository, notificationService,
                EXPIRATION_MINS, MAX_ATTEMPTS, true);
        JwtService jwtService = new JwtService(
                "test_jwt_access_secret_key_that_is_at_least_32_characters",
                900_000L, 604_800_000L);
        authService = new AuthService(
                userRepository, new BCryptPasswordEncoder(), jwtService, otpService, refreshTokenService);
    }

    @Test
    @DisplayName("verifyOtp marks user as verified on correct REGISTRATION code")
    void verifyOtp_correctCode_setsUserVerified() {
        String rawCode = "654321";
        String hash    = otpService.hashOtp(rawCode);

        OtpVerification verification = new OtpVerification(
                EMAIL, hash, OtpPurpose.REGISTRATION,
                Instant.now().plus(EXPIRATION_MINS, ChronoUnit.MINUTES));

        User user = buildUnverifiedUser(EMAIL);

        when(otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                eq(EMAIL), eq(OtpPurpose.REGISTRATION))).thenReturn(Optional.of(verification));
        when(otpRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(userRepository.findByEmailIgnoreCase(EMAIL)).thenReturn(Optional.of(user));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        VerifyOtpRequest req = new VerifyOtpRequest(EMAIL, rawCode, OtpPurpose.REGISTRATION);
        MessageResponse response = authService.verifyOtp(req);

        assertThat(response.message()).containsIgnoringCase("verified");
        verify(userRepository).save(argThat(User::isVerified));
    }

    @Test
    @DisplayName("verifyOtp throws OtpException when code is wrong")
    void verifyOtp_wrongCode_throwsOtpException() {
        String hash = otpService.hashOtp("111111");
        OtpVerification verification = new OtpVerification(
                EMAIL, hash, OtpPurpose.REGISTRATION,
                Instant.now().plus(EXPIRATION_MINS, ChronoUnit.MINUTES));

        when(otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                any(), any())).thenReturn(Optional.of(verification));
        when(otpRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        VerifyOtpRequest req = new VerifyOtpRequest(EMAIL, "999999", OtpPurpose.REGISTRATION);
        assertThatThrownBy(() -> authService.verifyOtp(req))
                .isInstanceOf(OtpException.class);
    }

    @Test
    @DisplayName("verifyOtp throws OtpException on expired OTP")
    void verifyOtp_expiredOtp_throwsOtpException() {
        String rawCode = "555555";
        String hash    = otpService.hashOtp(rawCode);

        OtpVerification expired = new OtpVerification(
                EMAIL, hash, OtpPurpose.REGISTRATION,
                Instant.now().minus(1, ChronoUnit.MINUTES)); // expired

        when(otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                any(), any())).thenReturn(Optional.of(expired));

        VerifyOtpRequest req = new VerifyOtpRequest(EMAIL, rawCode, OtpPurpose.REGISTRATION);
        assertThatThrownBy(() -> authService.verifyOtp(req))
                .isInstanceOf(OtpException.class)
                .hasMessageContaining("expired");
    }

    @Test
    @DisplayName("verifyOtp throws OtpException when no pending OTP exists")
    void verifyOtp_noPending_throwsOtpException() {
        when(otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                any(), any())).thenReturn(Optional.empty());

        VerifyOtpRequest req = new VerifyOtpRequest(EMAIL, "123456", OtpPurpose.REGISTRATION);
        assertThatThrownBy(() -> authService.verifyOtp(req))
                .isInstanceOf(OtpException.class)
                .hasMessageContaining("No pending");
    }

    @Test
    @DisplayName("verifyOtp throws AuthException when user not found after OTP success")
    void verifyOtp_userNotFound_throwsAuthException() {
        String rawCode = "777777";
        String hash    = otpService.hashOtp(rawCode);

        OtpVerification verification = new OtpVerification(
                EMAIL, hash, OtpPurpose.REGISTRATION,
                Instant.now().plus(EXPIRATION_MINS, ChronoUnit.MINUTES));

        when(otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                any(), any())).thenReturn(Optional.of(verification));
        when(otpRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(userRepository.findByEmailIgnoreCase(any())).thenReturn(Optional.empty());

        VerifyOtpRequest req = new VerifyOtpRequest(EMAIL, rawCode, OtpPurpose.REGISTRATION);
        assertThatThrownBy(() -> authService.verifyOtp(req))
                .isInstanceOf(AuthException.class);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private User buildUnverifiedUser(String email) {
        User u = new User();
        u.setId(10L);
        u.setEmail(email);
        u.setPasswordHash("$2a$10$hash");
        u.setRole("CUSTOMER");
        u.setVerified(false);
        u.setCreatedAt(Instant.now());
        u.setUpdatedAt(Instant.now());
        return u;
    }
}
