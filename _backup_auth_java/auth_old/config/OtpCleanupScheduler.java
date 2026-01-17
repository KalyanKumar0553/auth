package com.src.main.auth.config;

import java.time.LocalDateTime;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.src.main.auth.repository.OtpRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class OtpCleanupScheduler {

	private final OtpRepository otpRepository;

	@Scheduled(fixedRate = 5 * 60_000) // every 1 minute
	@Transactional
	public void cleanExpiredOtps() {
		LocalDateTime now = LocalDateTime.now();
		LocalDateTime deleteCutoff = now.minusMinutes(5);
		otpRepository.deleteOldExpiredOtps(deleteCutoff);
	}
}
