package com.iras.security;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JwtService — access-token generation and validation")
class JwtServiceTest {

    // 32+ char dev secret
    private static final String ACCESS_SECRET =
            "test_jwt_access_secret_key_that_is_at_least_32_characters";
    private static final long ACCESS_EXPIRATION_MS  = 900_000L;   // 15 min
    private static final long REFRESH_EXPIRATION_MS = 604_800_000L; // 7 days

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(ACCESS_SECRET, ACCESS_EXPIRATION_MS, REFRESH_EXPIRATION_MS);
    }

    // ── Access token ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("generateAccessToken produces a non-blank JWT")
    void generateAccessToken_producesNonBlank() {
        String token = jwtService.generateAccessToken(1L, "user@example.com", "CUSTOMER");
        assertThat(token).isNotBlank();
    }

    @Test
    @DisplayName("Generated token passes isAccessTokenValid")
    void generatedToken_isValid() {
        String token = jwtService.generateAccessToken(1L, "user@example.com", "CUSTOMER");
        assertThat(jwtService.isAccessTokenValid(token)).isTrue();
    }

    @Test
    @DisplayName("Claims contain userId, email (subject), and role")
    void parsedClaims_containExpectedFields() {
        String token = jwtService.generateAccessToken(42L, "jane@example.com", "ADMIN");
        Claims claims = jwtService.parseAndValidateAccessToken(token);

        assertThat(claims).isNotNull();
        assertThat(claims.getSubject()).isEqualTo("jane@example.com");
        assertThat(claims.get("userId", Long.class)).isEqualTo(42L);
        assertThat(claims.get("role", String.class)).isEqualTo("ADMIN");
    }

    @Test
    @DisplayName("Malformed token returns null claims")
    void malformedToken_returnsNull() {
        Claims claims = jwtService.parseAndValidateAccessToken("not.a.jwt");
        assertThat(claims).isNull();
    }

    @Test
    @DisplayName("Expired token fails isAccessTokenValid")
    void expiredToken_isInvalid() {
        // Create service with 0 ms expiry → immediately expired
        JwtService shortLived = new JwtService(ACCESS_SECRET, 0L, REFRESH_EXPIRATION_MS);
        String token = shortLived.generateAccessToken(1L, "user@example.com", "CUSTOMER");
        assertThat(shortLived.isAccessTokenValid(token)).isFalse();
    }

    @Test
    @DisplayName("Token signed by wrong key returns null claims")
    void wrongKey_returnsNullClaims() {
        JwtService otherService = new JwtService(
                "other_secret_key_that_is_at_least_32_characters_long", ACCESS_EXPIRATION_MS, REFRESH_EXPIRATION_MS);
        String tokenFromOther = otherService.generateAccessToken(1L, "user@example.com", "CUSTOMER");
        // Parse with original service → signature mismatch
        Claims claims = jwtService.parseAndValidateAccessToken(tokenFromOther);
        assertThat(claims).isNull();
    }

    // ── Refresh token string ──────────────────────────────────────────────────

    @Test
    @DisplayName("generateRefreshTokenString returns distinct values")
    void generateRefreshTokenString_isUnique() {
        String t1 = jwtService.generateRefreshTokenString();
        String t2 = jwtService.generateRefreshTokenString();
        assertThat(t1).isNotBlank();
        assertThat(t2).isNotBlank();
        assertThat(t1).isNotEqualTo(t2);
    }

    @Test
    @DisplayName("hashToken produces consistent SHA-256 hex")
    void hashToken_isConsistent() {
        String raw = "my-raw-token";
        String h1  = jwtService.hashToken(raw);
        String h2  = jwtService.hashToken(raw);
        assertThat(h1).isEqualTo(h2);
        assertThat(h1).hasSize(64); // SHA-256 hex = 64 chars
    }

    @Test
    @DisplayName("hashToken produces different hashes for different inputs")
    void hashToken_differentInputs_differentHashes() {
        assertThat(jwtService.hashToken("tokenA"))
                .isNotEqualTo(jwtService.hashToken("tokenB"));
    }

    // ── Expiration getters ────────────────────────────────────────────────────

    @Test
    @DisplayName("getAccessExpirationMs returns configured value")
    void getAccessExpirationMs_returnsConfigured() {
        assertThat(jwtService.getAccessExpirationMs()).isEqualTo(ACCESS_EXPIRATION_MS);
    }

    @Test
    @DisplayName("getRefreshExpirationMs returns configured value")
    void getRefreshExpirationMs_returnsConfigured() {
        assertThat(jwtService.getRefreshExpirationMs()).isEqualTo(REFRESH_EXPIRATION_MS);
    }
}
