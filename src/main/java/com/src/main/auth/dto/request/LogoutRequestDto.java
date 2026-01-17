package com.src.main.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;

public class LogoutRequestDto {
	@NotEmpty
	private String refreshToken;

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
}
