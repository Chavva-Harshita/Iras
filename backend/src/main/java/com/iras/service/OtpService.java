package com.iras.service;

import com.iras.entity.OtpPurpose;
import com.iras.entity.OtpVerification;
import com.iras.exception.OtpException;
import com.iras.repository.OtpVerificationRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OtpService {

    private final OtpVerificationRepository otpRepository;
    private final OtpNotificationService notificationService;
    private final int expirationMinutes;
    private final int maxAttempts;
    private final boolean exposeInDevResponse;
    private final SecureRandom secureRandom = new SecureRandom();

    public OtpService(
            OtpVerificationRepository otpRepository,
            OtpNotificationService notificationService,
            @Value("${iras.otp.expiration-minutes:10}") int expirationMinutes,
            @Value("${iras.otp.max-attempts:5}") int maxAttempts,
            @Value("${iras.otp.expose-in-dev-response:true}") boolean exposeInDevResponse) {
        this.otpRepository = otpRepository;
        this.notificationService = notificationService;
        this.expirationMinutes = expirationMinutes;
        this.maxAttempts = maxAttempts;
        this.exposeInDevResponse = exposeInDevResponse;
    }

    @Transactional
    public String generateAndSendOtp(String email, OtpPurpose purpose) {
        // Enforce 60-second resend cooldown if an active OTP was recently created
        otpRepository.findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(email, purpose)
                .ifPresent(existing -> {
                    long secondsSinceCreated = Duration.between(existing.getCreatedAt(), Instant.now()).toSeconds();
                    if (secondsSinceCreated < 60) {
                        throw new OtpException("Please wait " + (60 - secondsSinceCreated) + " seconds before requesting a new code.");
                    }
                });

        String code = String.format("%06d", secureRandom.nextInt(1_000_000));
        String codeHash = hashOtp(code);
        Instant expiresAt = Instant.now().plus(Duration.ofMinutes(expirationMinutes));

        OtpVerification verification = new OtpVerification(email, codeHash, purpose, expiresAt);
        otpRepository.save(verification);

        notificationService.sendOtp(email, code, purpose);

        return exposeInDevResponse ? code : null;
    }

    @Transactional
    public void verifyOtp(String email, String rawCode, OtpPurpose purpose) {
        OtpVerification verification = otpRepository
                .findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(email, purpose)
                .orElseThrow(() -> new OtpException("No pending verification code found for this email."));

        if (verification.isExpired()) {
            throw new OtpException("Verification code has expired. Please request a new one.");
        }

        if (verification.getAttempts() >= maxAttempts) {
            throw new OtpException("Too many invalid attempts. Please request a new verification code.");
        }

        String providedHash = hashOtp(rawCode);
        if (!providedHash.equals(verification.getOtpHash())) {
            verification.setAttempts(verification.getAttempts() + 1);
            otpRepository.save(verification);
            int remaining = maxAttempts - verification.getAttempts();
            throw new OtpException("Invalid verification code. " + remaining + " attempts remaining.");
        }

        verification.setConsumedAt(Instant.now());
        otpRepository.save(verification);
    }

    public String hashOtp(String rawCode) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(rawCode.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }

    public int getExpirationMinutes() {
        return expirationMinutes;
    }
}
