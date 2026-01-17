package com.src.main.auth.service;

import com.src.main.auth.model.IdentifierType;

public interface OtpSender {
	void send(IdentifierType type, String identifier, String otp);
}
