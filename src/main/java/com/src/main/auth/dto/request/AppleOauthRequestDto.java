package com.src.main.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;

public class AppleOauthRequestDto {
	@NotEmpty
	private String identityToken;

	public String getIdentityToken() {
		return identityToken;
	}

	public void setIdentityToken(String identityToken) {
		this.identityToken = identityToken;
	}
}
