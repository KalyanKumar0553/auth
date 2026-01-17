package com.src.main.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;

public class UpdateTenantVerificationDto {
	@NotEmpty
	private String identifier;
	private Boolean emailVerified;
	private Boolean mobileVerified;
	private Boolean ssnVerified;

	public String getIdentifier() {
		return identifier;
	}

	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}

	public Boolean getEmailVerified() {
		return emailVerified;
	}

	public void setEmailVerified(Boolean emailVerified) {
		this.emailVerified = emailVerified;
	}

	public Boolean getMobileVerified() {
		return mobileVerified;
	}

	public void setMobileVerified(Boolean mobileVerified) {
		this.mobileVerified = mobileVerified;
	}

	public Boolean getSsnVerified() {
		return ssnVerified;
	}

	public void setSsnVerified(Boolean ssnVerified) {
		this.ssnVerified = ssnVerified;
	}
}
