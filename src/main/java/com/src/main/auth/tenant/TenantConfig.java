package com.src.main.auth.tenant;

public class TenantConfig {
	private String id;
	private String tenantCode;
	private String displayName;
	private boolean isActive;
	private String shaKey;

	public TenantConfig() {}

	public TenantConfig(String id, String tenantCode, String displayName, boolean isActive, String shaKey) {
		this.id = id;
		this.tenantCode = tenantCode;
		this.displayName = displayName;
		this.isActive = isActive;
		this.shaKey = shaKey;
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

	public String getShaKey() {
		return shaKey;
	}

	public void setShaKey(String shaKey) {
		this.shaKey = shaKey;
	}
}
