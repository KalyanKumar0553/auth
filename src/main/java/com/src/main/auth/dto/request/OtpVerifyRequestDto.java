package com.src.main.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;

public class OtpVerifyRequestDto {
	@NotEmpty
	private String identifier;

	@NotEmpty
	@Pattern(regexp = "^\\d{6}$", message = "OTP must be 6 digits")
	private String otp;

	public String getIdentifier() {
		return identifier;
	}

	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}

	public String getOtp() {
		return otp;
	}

	public void setOtp(String otp) {
		this.otp = otp;
	}
}
