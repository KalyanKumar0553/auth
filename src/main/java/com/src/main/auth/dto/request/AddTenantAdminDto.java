package com.src.main.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;

public class AddTenantAdminDto {
	@NotEmpty
	private String identifier;

	public String getIdentifier() {
		return identifier;
	}

	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}
}
