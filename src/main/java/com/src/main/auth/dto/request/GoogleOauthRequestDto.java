package com.src.main.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;

public class GoogleOauthRequestDto {
	@NotEmpty
	private String idToken;

	public String getIdToken() {
		return idToken;
	}

	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}
}
