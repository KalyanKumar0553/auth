package com.src.main.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public class CreateTenantRequestDto {
	@NotEmpty
	private String tenantCode;

	@NotEmpty
	private String displayName;

	@NotEmpty
	private String shaKey;

	@NotNull
	private Boolean isActive;

	public String getTenantCode() {
		return tenantCode;
	}

	public void setTenantCode(String tenantCode) {
		this.tenantCode = tenantCode;
	}

	public String getDisplayName() {
		return displayName;
	}

	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}

	public String getShaKey() {
		return shaKey;
	}

	public void setShaKey(String shaKey) {
		this.shaKey = shaKey;
	}

	public Boolean getIsActive() {
		return isActive;
	}

	public void setIsActive(Boolean isActive) {
		this.isActive = isActive;
	}
}
