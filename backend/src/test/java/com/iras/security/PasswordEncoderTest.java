package com.iras.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("PasswordEncoder — BCrypt hashing and verification")
class PasswordEncoderTest {

    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        // Default BCrypt strength = 10
        passwordEncoder = new BCryptPasswordEncoder();
    }

    @Test
    @DisplayName("encode() never returns plaintext password")
    void encode_neverPlaintext() {
        String raw = "myS3cretP@ssword";
        String encoded = passwordEncoder.encode(raw);
        assertThat(encoded).isNotEqualTo(raw);
        assertThat(encoded).startsWith("$2a$"); // BCrypt prefix
    }

    @Test
    @DisplayName("encode() produces different salts each call")
    void encode_differentSaltsEachCall() {
        String raw = "password123";
        String h1 = passwordEncoder.encode(raw);
        String h2 = passwordEncoder.encode(raw);
        assertThat(h1).isNotEqualTo(h2);
    }

    @Test
    @DisplayName("matches() returns true for correct password")
    void matches_correctPassword_returnsTrue() {
        String raw = "correctPassword!";
        String hash = passwordEncoder.encode(raw);
        assertThat(passwordEncoder.matches(raw, hash)).isTrue();
    }

    @Test
    @DisplayName("matches() returns false for wrong password")
    void matches_wrongPassword_returnsFalse() {
        String hash = passwordEncoder.encode("correctPassword!");
        assertThat(passwordEncoder.matches("wrongPassword!", hash)).isFalse();
    }

    @Test
    @DisplayName("matches() returns false for empty string")
    void matches_emptyString_returnsFalse() {
        String hash = passwordEncoder.encode("correctPassword!");
        assertThat(passwordEncoder.matches("", hash)).isFalse();
    }
}
