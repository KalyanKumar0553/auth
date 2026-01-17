package com.src.main.auth.repository;

import java.time.Instant;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.src.main.auth.model.OtpPurpose;
import com.src.main.auth.model.OtpRequest;

public interface OtpRequestRepository extends JpaRepository<OtpRequest, String> {
	Optional<OtpRequest> findFirstByUserIdAndPurposeAndUsedFalseOrderByCreatedAtDesc(String userId, OtpPurpose purpose);
	long countByUserIdAndCreatedAtBetween(String userId, Instant start, Instant end);
}
