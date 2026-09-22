package com.iras.service;

import com.iras.entity.RefreshToken;
import com.iras.entity.User;
import com.iras.exception.TokenRefreshException;
import com.iras.repository.RefreshTokenRepository;
import com.iras.security.JwtService;
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
@DisplayName("RefreshTokenService — rotation, revocation, replay detection")
class RefreshTokenServiceTest {

    @Mock private RefreshTokenRepository refreshTokenRepository;

    private JwtService jwtService;
    private RefreshTokenService refreshTokenService;

    private static final long REFRESH_EXP_MS = 604_800_000L;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(
                "test_jwt_access_secret_key_that_is_at_least_32_characters",
                900_000L, REFRESH_EXP_MS);
        refreshTokenService = new RefreshTokenService(refreshTokenRepository, jwtService);
    }

    // ── createRefreshToken ────────────────────────────────────────────────────

    @Test
    @DisplayName("createRefreshToken stores hash (not raw token) and returns raw token")
    void createRefreshToken_storesHashReturnsRaw() {
        User user = buildUser(1L, "alice@example.com");
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        String rawToken = refreshTokenService.createRefreshToken(user);
        assertThat(rawToken).isNotBlank();

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());

        RefreshToken saved = captor.getValue();
        // Stored hash must NOT equal raw token
        assertThat(saved.getTokenHash()).isNotEqualTo(rawToken);
        assertThat(saved.getTokenHash()).hasSize(64); // SHA-256 hex
        assertThat(saved.isRevoked()).isFalse();
    }

    @Test
    @DisplayName("Two createRefreshToken calls produce different raw tokens")
    void createRefreshToken_producesUniqueRawTokens() {
        User user = buildUser(1L, "alice@example.com");
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        String t1 = refreshTokenService.createRefreshToken(user);
        String t2 = refreshTokenService.createRefreshToken(user);
        assertThat(t1).isNotEqualTo(t2);
    }

    // ── rotateRefreshToken ────────────────────────────────────────────────────

    @Test
    @DisplayName("rotateRefreshToken revokes old token and issues new one")
    void rotateRefreshToken_success() {
        User user = buildUser(1L, "alice@example.com");
        String oldRaw   = jwtService.generateRefreshTokenString();
        String oldHash  = jwtService.hashToken(oldRaw);
        RefreshToken oldToken = buildActiveToken(user, oldHash);

        when(refreshTokenRepository.findByTokenHash(oldHash)).thenReturn(Optional.of(oldToken));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        RefreshTokenService.RotatedToken result = refreshTokenService.rotateRefreshToken(oldRaw);

        assertThat(result.newRawToken()).isNotBlank();
        assertThat(result.newRawToken()).isNotEqualTo(oldRaw);
        assertThat(result.user().getEmail()).isEqualTo("alice@example.com");

        // Old token must be marked revoked
        assertThat(oldToken.isRevoked()).isTrue();
        assertThat(oldToken.getRevokedAt()).isNotNull();
    }

    @Test
    @DisplayName("rotateRefreshToken throws on already-revoked token (replay detection)")
    void rotateRefreshToken_revokedToken_invalidatesAllAndThrows() {
        User user = buildUser(1L, "alice@example.com");
        String oldRaw  = jwtService.generateRefreshTokenString();
        String oldHash = jwtService.hashToken(oldRaw);
        RefreshToken revokedToken = buildRevokedToken(user, oldHash);

        when(refreshTokenRepository.findByTokenHash(oldHash)).thenReturn(Optional.of(revokedToken));

        assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken(oldRaw))
                .isInstanceOf(TokenRefreshException.class)
                .hasMessageContaining("reuse detected");

        // All tokens for user should be revoked (nuclear option)
        verify(refreshTokenRepository).revokeAllByUserId(eq(1L), any(Instant.class));
    }

    @Test
    @DisplayName("rotateRefreshToken throws on expired token")
    void rotateRefreshToken_expiredToken_throws() {
        User user = buildUser(1L, "alice@example.com");
        String oldRaw  = jwtService.generateRefreshTokenString();
        String oldHash = jwtService.hashToken(oldRaw);
        RefreshToken expiredToken = buildExpiredToken(user, oldHash);

        when(refreshTokenRepository.findByTokenHash(oldHash)).thenReturn(Optional.of(expiredToken));

        assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken(oldRaw))
                .isInstanceOf(TokenRefreshException.class)
                .hasMessageContaining("expired");
    }

    @Test
    @DisplayName("rotateRefreshToken throws on unknown token hash")
    void rotateRefreshToken_unknownToken_throws() {
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken("unknown-raw-token"))
                .isInstanceOf(TokenRefreshException.class)
                .hasMessageContaining("Invalid");
    }

    // ── revokeRefreshToken ────────────────────────────────────────────────────

    @Test
    @DisplayName("revokeRefreshToken marks token revoked and sets revokedAt")
    void revokeRefreshToken_marksRevokedAndTimestamp() {
        User user = buildUser(1L, "alice@example.com");
        String raw  = jwtService.generateRefreshTokenString();
        String hash = jwtService.hashToken(raw);
        RefreshToken token = buildActiveToken(user, hash);

        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(token));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        refreshTokenService.revokeRefreshToken(raw);

        assertThat(token.isRevoked()).isTrue();
        assertThat(token.getRevokedAt()).isNotNull();
    }

    @Test
    @DisplayName("revokeRefreshToken with null/blank does nothing")
    void revokeRefreshToken_nullOrBlank_doesNothing() {
        assertThatCode(() -> refreshTokenService.revokeRefreshToken(null))
                .doesNotThrowAnyException();
        assertThatCode(() -> refreshTokenService.revokeRefreshToken("  "))
                .doesNotThrowAnyException();
        verify(refreshTokenRepository, never()).findByTokenHash(any());
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private User buildUser(Long id, String email) {
        User u = new User();
        u.setId(id);
        u.setEmail(email);
        u.setRole("CUSTOMER");
        u.setVerified(true);
        return u;
    }

    private RefreshToken buildActiveToken(User user, String hash) {
        return new RefreshToken(user, hash,
                Instant.now().plus(7, ChronoUnit.DAYS));
    }

    private RefreshToken buildRevokedToken(User user, String hash) {
        RefreshToken t = new RefreshToken(user, hash,
                Instant.now().plus(7, ChronoUnit.DAYS));
        t.setRevoked(true);
        t.setRevokedAt(Instant.now().minus(1, ChronoUnit.HOURS));
        return t;
    }

    private RefreshToken buildExpiredToken(User user, String hash) {
        return new RefreshToken(user, hash,
                Instant.now().minus(1, ChronoUnit.HOURS)); // already expired
    }
}
