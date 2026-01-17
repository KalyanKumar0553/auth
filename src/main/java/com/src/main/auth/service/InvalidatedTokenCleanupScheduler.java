package com.src.main.auth.service;

import java.time.Instant;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.src.main.auth.repository.InvalidatedTokenRepository;

@Service
public class InvalidatedTokenCleanupScheduler {
	private final InvalidatedTokenRepository invalidatedTokenRepository;
	private final String cleanupDelayMs;

	public InvalidatedTokenCleanupScheduler(
			InvalidatedTokenRepository invalidatedTokenRepository,
			@Value("${security.invalidated.cleanup.ms:3600000}") String cleanupDelayMs) {
		this.invalidatedTokenRepository = invalidatedTokenRepository;
		this.cleanupDelayMs = cleanupDelayMs;
	}

	@Scheduled(fixedDelayString = "${security.invalidated.cleanup.ms:3600000}")
	public void cleanupExpired() {
		invalidatedTokenRepository.deleteByExpiresAtBefore(Instant.now());
	}

	public String getCleanupDelayMs() {
		return cleanupDelayMs;
	}
}
