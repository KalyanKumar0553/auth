package com.src.main.auth.model;

import java.io.Serializable;
import java.util.Objects;

public class UserTenantVerificationId implements Serializable {
	private String userId;
	private String tenantId;

	public UserTenantVerificationId() {}

	public UserTenantVerificationId(String userId, String tenantId) {
		this.userId = userId;
		this.tenantId = tenantId;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		UserTenantVerificationId that = (UserTenantVerificationId) o;
		return Objects.equals(userId, that.userId) && Objects.equals(tenantId, that.tenantId);
	}

	@Override
	public int hashCode() {
		return Objects.hash(userId, tenantId);
	}
}
