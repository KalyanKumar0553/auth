package com.src.main.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;

public class TenantRoleInputDto {
	@NotEmpty
	private String name;

	private Boolean isActive;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Boolean getIsActive() {
		return isActive;
	}

	public void setIsActive(Boolean isActive) {
		this.isActive = isActive;
	}
}
