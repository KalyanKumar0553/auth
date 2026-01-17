package com.src.main.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;

public class TokenValidateRequestDto {
	@NotEmpty
	private String token;

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}
}
