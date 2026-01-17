package com.src.main.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;

public class LoginRequestDto {
	@NotEmpty
	private String identifier;

	@NotEmpty
	private String password;

	public String getIdentifier() {
		return identifier;
	}

	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
