package com.src.main.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.src.main.auth.model.IdentifierType;

@Component
public class LoggingOtpSender implements OtpSender {
	private static final Logger LOG = LoggerFactory.getLogger(LoggingOtpSender.class);

	@Override
	public void send(IdentifierType type, String identifier, String otp) {
		LOG.info("OTP({}) to {} => {}", type, identifier, otp);
	}
}
