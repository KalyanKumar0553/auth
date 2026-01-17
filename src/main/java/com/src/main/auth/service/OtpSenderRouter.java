package com.src.main.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.src.main.auth.model.IdentifierType;

@Component
public class OtpSenderRouter implements OtpSender {
	private final String mode;
	private final LoggingOtpSender logging;
	private final CommunicationOtpSender communication;

	public OtpSenderRouter(
			@Value("${otp.channel.mode:LOGGING}") String mode,
			LoggingOtpSender logging,
			CommunicationOtpSender communication) {
		this.mode = mode == null ? "LOGGING" : mode.toUpperCase();
		this.logging = logging;
		this.communication = communication;
	}

	@Override
	public void send(IdentifierType type, String identifier, String otp) {
		if ("LOGGING".equals(mode)) {
			logging.send(type, identifier, otp);
			return;
		}
		communication.send(type, identifier, otp);
	}
}
