package com.iras.service;

import com.iras.entity.OtpPurpose;
import com.iras.entity.OtpVerification;
import com.iras.exception.OtpException;
import com.iras.repository.OtpVerificationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("OtpService — generation and verification")
class OtpServiceTest {

    @Mock private OtpVerificationRepository otpRepository;
    @Mock private OtpNotificationService notificationService;

    private OtpService otpService;

    private static final int EXPIRATION_MINUTES = 10;
    private static final int MAX_ATTEMPTS       = 5;
    private static final String EMAIL           = "test@example.com";

    @BeforeEach
    void setUp() {
        otpService = new OtpService(otpRepository, notificationService,
                EXPIRATION_MINUTES, MAX_ATTEMPTS, /* exposeInDevResponse */ true);
    }

    // ── Generation ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("generateAndSendOtp saves OTP hash (not plaintext) to repository")
    void generateOtp_savesHashNotPlaintext() {
        when(otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                any(), any())).thenReturn(Optional.empty());

        ArgumentCaptor<OtpVerification> captor = ArgumentCaptor.forClass(OtpVerification.class);
        when(otpRepository.save(captor.capture())).thenAnswer(inv -> inv.getArgument(0));

        String devOtp = otpService.generateAndSendOtp(EMAIL, OtpPurpose.REGISTRATION);

        assertThat(devOtp).isNotBlank().matches("\\d{6}");

        OtpVerification saved = captor.getValue();
        // The hash stored must NOT equal the raw 6-digit code
        assertThat(saved.getOtpHash()).isNotEqualTo(devOtp);
        // Hash should be a 64-char SHA-256 hex string
        assertThat(saved.getOtpHash()).hasSize(64);
    }

    @Test
    @DisplayName("generateAndSendOtp returns null when devResponse disabled")
    void generateOtp_devResponseDisabled_returnsNull() {
        OtpService hiddenService = new OtpService(otpRepository, notificationService,
                EXPIRATION_MINUTES, MAX_ATTEMPTS, /* expose = */ false);

        when(otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                any(), any())).thenReturn(Optional.empty());
        when(otpRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        String result = hiddenService.generateAndSendOtp(EMAIL, OtpPurpose.REGISTRATION);
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("generateAndSendOtp enforces 60-second resend cooldown")
    void generateOtp_cooldown_throwsOtpException() {
        OtpVerification recent = buildVerification(EMAIL, "recentHash", 0 /* seconds old */);
        when(otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                any(), any())).thenReturn(Optional.of(recent));

        assertThatThrownBy(() -> otpService.generateAndSendOtp(EMAIL, OtpPurpose.REGISTRATION))
                .isInstanceOf(OtpException.class)
                .hasMessageContaining("wait");
    }

    // ── Verification ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("verifyOtp succeeds with correct code")
    void verifyOtp_correctCode_succeeds() {
        String rawCode = "123456";
        String hash = otpService.hashOtp(rawCode);
        OtpVerification verification = buildVerification(EMAIL, hash, 120);

        when(otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                eq(EMAIL), eq(OtpPurpose.REGISTRATION))).thenReturn(Optional.of(verification));
        when(otpRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        assertThatCode(() -> otpService.verifyOtp(EMAIL, rawCode, OtpPurpose.REGISTRATION))
                .doesNotThrowAnyException();

        // consumedAt must be set
        verify(otpRepository).save(argThat(v -> v.getConsumedAt() != null));
    }

    @Test
    @DisplayName("verifyOtp throws OtpException for wrong code and increments attempts")
    void verifyOtp_wrongCode_incrementsAttempts() {
        String hash = otpService.hashOtp("123456");
        OtpVerification verification = buildVerification(EMAIL, hash, 120);

        when(otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                any(), any())).thenReturn(Optional.of(verification));
        when(otpRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        assertThatThrownBy(() -> otpService.verifyOtp(EMAIL, "999999", OtpPurpose.REGISTRATION))
                .isInstanceOf(OtpException.class)
                .hasMessageContaining("Invalid");

        verify(otpRepository).save(argThat(v -> v.getAttempts() == 1));
    }

    @Test
    @DisplayName("verifyOtp throws OtpException when expired")
    void verifyOtp_expired_throwsOtpException() {
        String hash = otpService.hashOtp("123456");
        OtpVerification expired = buildExpiredVerification(EMAIL, hash);

        when(otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                any(), any())).thenReturn(Optional.of(expired));

        assertThatThrownBy(() -> otpService.verifyOtp(EMAIL, "123456", OtpPurpose.REGISTRATION))
                .isInstanceOf(OtpException.class)
                .hasMessageContaining("expired");
    }

    @Test
    @DisplayName("verifyOtp throws OtpException when max attempts exceeded")
    void verifyOtp_tooManyAttempts_throwsOtpException() {
        String hash = otpService.hashOtp("123456");
        OtpVerification locked = buildVerification(EMAIL, hash, 120);
        locked.setAttempts(MAX_ATTEMPTS); // already at limit

        when(otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                any(), any())).thenReturn(Optional.of(locked));

        assertThatThrownBy(() -> otpService.verifyOtp(EMAIL, "123456", OtpPurpose.REGISTRATION))
                .isInstanceOf(OtpException.class)
                .hasMessageContaining("Too many");
    }

    @Test
    @DisplayName("verifyOtp throws OtpException when no pending OTP found")
    void verifyOtp_noPending_throwsOtpException() {
        when(otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                any(), any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> otpService.verifyOtp(EMAIL, "123456", OtpPurpose.REGISTRATION))
                .isInstanceOf(OtpException.class)
                .hasMessageContaining("No pending");
    }

    // ── Hashing ───────────────────────────────────────────────────────────────

    @Test
    @DisplayName("hashOtp is deterministic and returns 64-char hex")
    void hashOtp_deterministic() {
        String h1 = otpService.hashOtp("654321");
        String h2 = otpService.hashOtp("654321");
        assertThat(h1).isEqualTo(h2).hasSize(64);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private OtpVerification buildVerification(String email, String hash, int secondsOld) {
        OtpVerification v = new OtpVerification(
                email, hash, OtpPurpose.REGISTRATION,
                Instant.now().plus(EXPIRATION_MINUTES, ChronoUnit.MINUTES));
        // Simulate creation time so cooldown check works correctly
        v.setCreatedAt(Instant.now().minus(secondsOld, ChronoUnit.SECONDS));
        return v;
    }

    private OtpVerification buildExpiredVerification(String email, String hash) {
        OtpVerification v = new OtpVerification(
                email, hash, OtpPurpose.REGISTRATION,
                Instant.now().minus(1, ChronoUnit.MINUTES)); // already expired
        return v;
    }
}
