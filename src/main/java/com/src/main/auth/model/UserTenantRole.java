package com.src.main.auth.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "user_tenant_roles")
@IdClass(UserTenantRoleId.class)
public class UserTenantRole {
	@jakarta.persistence.Id
	@Column(name = "user_id", nullable = false)
	private String userId;

	@jakarta.persistence.Id
	@Column(name = "tenant_role_id", nullable = false)
	private String tenantRoleId;

	@ManyToOne
	@JoinColumn(name = "user_id", referencedColumnName = "id", insertable = false, updatable = false)
	private User user;

	@ManyToOne
	@JoinColumn(name = "tenant_role_id", referencedColumnName = "id", insertable = false, updatable = false)
	private TenantRole tenantRole;

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getTenantRoleId() {
		return tenantRoleId;
	}

	public void setTenantRoleId(String tenantRoleId) {
		this.tenantRoleId = tenantRoleId;
	}

	public TenantRole getTenantRole() {
		return tenantRole;
	}
}
