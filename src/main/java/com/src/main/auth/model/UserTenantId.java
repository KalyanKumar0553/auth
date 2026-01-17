package com.src.main.auth.model;

import java.io.Serializable;
import java.util.Objects;

public class UserTenantId implements Serializable {
	private String userId;
	private String tenantId;

	public UserTenantId() {}

	public UserTenantId(String userId, String tenantId) {
		this.userId = userId;
		this.tenantId = tenantId;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		UserTenantId that = (UserTenantId) o;
		return Objects.equals(userId, that.userId) && Objects.equals(tenantId, that.tenantId);
	}

	@Override
	public int hashCode() {
		return Objects.hash(userId, tenantId);
	}
}
