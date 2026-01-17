package com.src.main.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.src.main.auth.model.IdentifierType;
import com.src.main.communication.service.MsgService;

@Component
public class CommunicationOtpSender implements OtpSender {
	private final MsgService msgService;
	private final String emailSender;
	private final String smsSender;

	public CommunicationOtpSender(
			MsgService msgService,
			@Value("${otp.email.sender:}") String emailSender,
			@Value("${otp.sms.sender:}") String smsSender) {
		this.msgService = msgService;
		this.emailSender = emailSender;
		this.smsSender = smsSender;
	}

	@Override
	public void send(IdentifierType type, String identifier, String otp) {
		if (type == IdentifierType.EMAIL) {
			String html = "<html><body><p>Your OTP code is: <strong>" + otp + "</strong></p></body></html>";
			msgService.sendEmail(emailSender, identifier, "Your OTP", html);
			return;
		}
		msgService.sendSMS(smsSender, identifier, "Your OTP is: " + otp);
	}
}
