package com.src.main.auth.model;

import java.io.Serializable;
import java.util.Objects;

public class UserTenantRoleId implements Serializable {
	private String userId;
	private String tenantRoleId;

	public UserTenantRoleId() {}

	public UserTenantRoleId(String userId, String tenantRoleId) {
		this.userId = userId;
		this.tenantRoleId = tenantRoleId;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		UserTenantRoleId that = (UserTenantRoleId) o;
		return Objects.equals(userId, that.userId) && Objects.equals(tenantRoleId, that.tenantRoleId);
	}

	@Override
	public int hashCode() {
		return Objects.hash(userId, tenantRoleId);
	}
}
