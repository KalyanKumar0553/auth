package com.src.main.auth.repository;

import java.time.LocalDateTime;
import org.springframework.data.repository.query.Param;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import com.src.main.auth.model.OtpAttempt;

public interface OtpAttemptRepository extends JpaRepository<OtpAttempt, Long> {

	Optional<OtpAttempt> findByUsernameAndCreatedAtBetweenOrderByCreatedAtDesc(String username, LocalDateTime startTime,
			LocalDateTime endTime);

	@Transactional
	@Modifying
	@Query(value = "DELETE FROM OtpAttempt o WHERE o.username = :username")
	void deleteAllByUsername(@Param("username") String username);

}
