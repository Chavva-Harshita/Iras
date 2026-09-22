package com.iras.service;

import com.iras.entity.RefreshToken;
import com.iras.entity.User;
import com.iras.exception.TokenRefreshException;
import com.iras.repository.RefreshTokenRepository;
import com.iras.security.JwtService;
import java.time.Duration;
import java.time.Instant;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, JwtService jwtService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtService = jwtService;
    }

    @Transactional
    public String createRefreshToken(User user) {
        String rawToken = jwtService.generateRefreshTokenString();
        String tokenHash = jwtService.hashToken(rawToken);
        Instant expiresAt = Instant.now().plus(Duration.ofMillis(jwtService.getRefreshExpirationMs()));

        RefreshToken refreshToken = new RefreshToken(user, tokenHash, expiresAt);
        refreshTokenRepository.save(refreshToken);
        return rawToken;
    }

    public record RotatedToken(User user, String newRawToken) {
    }

    @Transactional
    public RotatedToken rotateRefreshToken(String rawOldToken) {
        if (rawOldToken == null || rawOldToken.isBlank()) {
            throw new TokenRefreshException("Refresh token is missing.");
        }

        String oldHash = jwtService.hashToken(rawOldToken);
        RefreshToken oldToken = refreshTokenRepository.findByTokenHash(oldHash)
                .orElseThrow(() -> new TokenRefreshException("Invalid refresh token."));

        if (oldToken.isRevoked()) {
            // Potential replay / token theft detected. Invalidate all tokens for this user!
            refreshTokenRepository.revokeAllByUserId(oldToken.getUser().getId(), Instant.now());
            throw new TokenRefreshException("Refresh token reuse detected. Session terminated.");
        }

        if (oldToken.isExpired()) {
            throw new TokenRefreshException("Refresh token has expired. Please log in again.");
        }

        // Revoke old token
        oldToken.setRevoked(true);
        oldToken.setRevokedAt(Instant.now());

        // Issue new token
        String newRawToken = jwtService.generateRefreshTokenString();
        String newHash = jwtService.hashToken(newRawToken);
        Instant expiresAt = Instant.now().plus(Duration.ofMillis(jwtService.getRefreshExpirationMs()));

        oldToken.setReplacedByTokenHash(newHash);
        refreshTokenRepository.save(oldToken);

        RefreshToken newToken = new RefreshToken(oldToken.getUser(), newHash, expiresAt);
        refreshTokenRepository.save(newToken);

        return new RotatedToken(oldToken.getUser(), newRawToken);
    }

    @Transactional
    public void revokeRefreshToken(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return;
        }
        String tokenHash = jwtService.hashToken(rawToken);
        refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token -> {
            token.setRevoked(true);
            token.setRevokedAt(Instant.now());
            refreshTokenRepository.save(token);
        });
    }

    @Transactional
    public void revokeAllForUser(Long userId) {
        refreshTokenRepository.revokeAllByUserId(userId, Instant.now());
    }
}
