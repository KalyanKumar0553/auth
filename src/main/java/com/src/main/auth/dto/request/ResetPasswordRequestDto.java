package com.src.main.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class ResetPasswordRequestDto {
	@NotEmpty
	private String identifier;

	@NotEmpty
	@Pattern(regexp = "^\\d{6}$", message = "OTP must be 6 digits")
	private String otp;

	@NotEmpty
	@Size(min = 8, max = 72)
	private String newPassword;

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

	public String getNewPassword() {
		return newPassword;
	}

	public void setNewPassword(String newPassword) {
		this.newPassword = newPassword;
	}
}
