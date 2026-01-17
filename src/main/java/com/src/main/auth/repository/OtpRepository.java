package com.src.main.auth.repository;


import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import com.src.main.auth.model.Otp;


public interface OtpRepository extends JpaRepository<Otp, Long> {

	Optional<Otp> findFirstByUsernameOrderByCreatedAtDesc(String username);

    Optional<Otp> findFirstByUsernameAndCreatedAtBetweenOrderByCreatedAtDesc(String username,LocalDateTime startTime,LocalDateTime endTime);

	@Transactional
	@Modifying
	@Query(value = "DELETE FROM Otp o WHERE o.username = :username")
	void deleteAllByUsername(@Param("username") String username);
	
	@Modifying
    @Query("DELETE FROM Otp o WHERE o.createdAt < :cleanupTime")
    int deleteOldExpiredOtps(@Param("cleanupTime") LocalDateTime cleanupTime);
}
