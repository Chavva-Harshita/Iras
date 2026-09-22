package com.iras.repository;

import com.iras.entity.OtpPurpose;
import com.iras.entity.OtpVerification;
import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OtpVerificationRepository extends JpaRepository<OtpVerification, Long> {

    Optional<OtpVerification> findTopByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
            String email, OtpPurpose purpose);

    Optional<OtpVerification> findTopByEmailIgnoreCaseAndPurposeOrderByCreatedAtDesc(
            String email, OtpPurpose purpose);

    void deleteByExpiresAtBefore(Instant time);
}
