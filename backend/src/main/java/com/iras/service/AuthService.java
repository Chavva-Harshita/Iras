package com.iras.service;

import com.iras.dto.auth.AuthResponse;
import com.iras.dto.auth.LoginRequest;
import com.iras.dto.auth.MessageResponse;
import com.iras.dto.auth.OtpSentResponse;
import com.iras.dto.auth.RegisterRequest;
import com.iras.dto.auth.ResendOtpRequest;
import com.iras.dto.auth.UserSummaryDto;
import com.iras.dto.auth.VerifyOtpRequest;
import com.iras.entity.OtpPurpose;
import com.iras.entity.User;
import com.iras.exception.AuthException;
import com.iras.repository.UserRepository;
import com.iras.security.JwtService;
import java.time.Instant;
import java.util.Optional;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final OtpService otpService;
    private final RefreshTokenService refreshTokenService;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            OtpService otpService,
            RefreshTokenService refreshTokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.otpService = otpService;
        this.refreshTokenService = refreshTokenService;
    }

    public record LoginResult(AuthResponse response, String rawRefreshToken) {
    }

    @Transactional
    public OtpSentResponse register(RegisterRequest request) {
        String normalizedEmail = request.email().trim().toLowerCase();
        Optional<User> existingOpt = userRepository.findByEmailIgnoreCase(normalizedEmail);

        User user;
        if (existingOpt.isPresent()) {
            user = existingOpt.get();
            if (user.isVerified()) {
                throw new AuthException("An account with this email already exists.");
            }
            // Update existing unverified registration
            user.setPasswordHash(passwordEncoder.encode(request.password()));
            user.setFirstName(request.firstName().trim());
            user.setLastName(request.lastName().trim());
            user.setPhone(request.phone() != null ? request.phone().trim() : null);
            user.setUpdatedAt(Instant.now());
        } else {
            user = new User();
            user.setEmail(normalizedEmail);
            user.setPasswordHash(passwordEncoder.encode(request.password()));
            user.setFirstName(request.firstName().trim());
            user.setLastName(request.lastName().trim());
            user.setPhone(request.phone() != null ? request.phone().trim() : null);
            user.setRole("CUSTOMER");
            user.setVerified(false);
            user.setCreatedAt(Instant.now());
            user.setUpdatedAt(Instant.now());
        }
        userRepository.save(user);

        String devOtp = otpService.generateAndSendOtp(normalizedEmail, OtpPurpose.REGISTRATION);

        return new OtpSentResponse(
                "Registration initiated. Please verify your email with the OTP sent.",
                normalizedEmail,
                OtpPurpose.REGISTRATION.name(),
                otpService.getExpirationMinutes(),
                devOtp
        );
    }

    @Transactional
    public MessageResponse verifyOtp(VerifyOtpRequest request) {
        String normalizedEmail = request.email().trim().toLowerCase();
        otpService.verifyOtp(normalizedEmail, request.otpCode().trim(), request.purpose());

        if (request.purpose() == OtpPurpose.REGISTRATION) {
            User user = userRepository.findByEmailIgnoreCase(normalizedEmail)
                    .orElseThrow(() -> new AuthException("User not found for this email."));
            user.setVerified(true);
            user.setUpdatedAt(Instant.now());
            userRepository.save(user);
        }

        return new MessageResponse("Email successfully verified. You can now log in.");
    }

    @Transactional
    public OtpSentResponse resendOtp(ResendOtpRequest request) {
        String normalizedEmail = request.email().trim().toLowerCase();
        User user = userRepository.findByEmailIgnoreCase(normalizedEmail)
                .orElseThrow(() -> new AuthException("No account found with this email."));

        if (request.purpose() == OtpPurpose.REGISTRATION && user.isVerified()) {
            throw new AuthException("Account is already verified. Please log in.");
        }

        String devOtp = otpService.generateAndSendOtp(normalizedEmail, request.purpose());

        return new OtpSentResponse(
                "A new verification code has been sent.",
                normalizedEmail,
                request.purpose().name(),
                otpService.getExpirationMinutes(),
                devOtp
        );
    }

    @Transactional
    public LoginResult login(LoginRequest request) {
        String normalizedEmail = request.email().trim().toLowerCase();
        User user = userRepository.findByEmailIgnoreCase(normalizedEmail)
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password."));

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new BadCredentialsException("Invalid email or password.");
        }

        if (!user.isVerified()) {
            throw new AuthException("Account not verified. Please verify your email first.");
        }

        String accessToken = jwtService.generateAccessToken(user.getId(), user.getEmail(), user.getRole());
        String rawRefreshToken = refreshTokenService.createRefreshToken(user);

        AuthResponse authResponse = AuthResponse.bearer(
                accessToken,
                jwtService.getAccessExpirationMs(),
                UserSummaryDto.fromEntity(user)
        );

        return new LoginResult(authResponse, rawRefreshToken);
    }

    @Transactional
    public LoginResult refreshToken(String rawRefreshToken) {
        RefreshTokenService.RotatedToken rotated = refreshTokenService.rotateRefreshToken(rawRefreshToken);
        User user = rotated.user();

        String newAccessToken = jwtService.generateAccessToken(user.getId(), user.getEmail(), user.getRole());

        AuthResponse authResponse = AuthResponse.bearer(
                newAccessToken,
                jwtService.getAccessExpirationMs(),
                UserSummaryDto.fromEntity(user)
        );

        return new LoginResult(authResponse, rotated.newRawToken());
    }

    @Transactional
    public void logout(String rawRefreshToken) {
        refreshTokenService.revokeRefreshToken(rawRefreshToken);
    }

    @Transactional(readOnly = true)
    public UserSummaryDto getCurrentUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException("User not found."));
        return UserSummaryDto.fromEntity(user);
    }
}
