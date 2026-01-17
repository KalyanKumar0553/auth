package com.src.main.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Component
@ConfigurationProperties(prefix = "communication.otp")
@Data
public class OtpConfig {

	/**
	 * Maps to property: communication.otp.max_attempts Default: 10
	 */
	private int maxAttempts = 10;

	/**
	 * Maps to property: communication.otp.otp_validitiy_minutes NOTE: field name
	 * keeps the same spelling as property. Default: 3
	 */
	private int otpValiditiyMinutes = 3;
}
