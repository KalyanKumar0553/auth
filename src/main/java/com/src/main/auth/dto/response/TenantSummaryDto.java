package com.src.main.auth.dto.response;

public class TenantSummaryDto {
	private String id;
	private String tenantCode;
	private String displayName;
	private boolean isActive;

	public TenantSummaryDto() {}

	public TenantSummaryDto(String id, String tenantCode, String displayName, boolean isActive) {
		this.id = id;
		this.tenantCode = tenantCode;
		this.displayName = displayName;
		this.isActive = isActive;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

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

	public boolean isActive() {
		return isActive;
	}

	public void setActive(boolean active) {
		isActive = active;
	}
}
