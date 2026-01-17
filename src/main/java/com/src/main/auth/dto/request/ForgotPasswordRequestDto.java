package com.src.main.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;

public class ForgotPasswordRequestDto {
	@NotEmpty
	private String identifier;

	@NotEmpty
	private String captchaId;

	@NotEmpty
	private String captchaText;

	public String getIdentifier() {
		return identifier;
	}

	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}

	public String getCaptchaId() {
		return captchaId;
	}

	public void setCaptchaId(String captchaId) {
		this.captchaId = captchaId;
	}

	public String getCaptchaText() {
		return captchaText;
	}

	public void setCaptchaText(String captchaText) {
		this.captchaText = captchaText;
	}
}
