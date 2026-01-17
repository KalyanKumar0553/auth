package com.src.main.auth.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "user_tenants")
@IdClass(UserTenantId.class)
public class UserTenant {
	@jakarta.persistence.Id
	@Column(name = "user_id", nullable = false)
	private String userId;

	@jakarta.persistence.Id
	@Column(name = "tenant_id", nullable = false)
	private String tenantId;

	@Column(name = "is_active", nullable = false)
	private boolean isActive = true;

	@ManyToOne
	@JoinColumn(name = "user_id", referencedColumnName = "id", insertable = false, updatable = false)
	private User user;

	@ManyToOne
	@JoinColumn(name = "tenant_id", referencedColumnName = "id", insertable = false, updatable = false)
	private Tenant tenant;

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getTenantId() {
		return tenantId;
	}

	public void setTenantId(String tenantId) {
		this.tenantId = tenantId;
	}

	public boolean isActive() {
		return isActive;
	}

	public void setActive(boolean active) {
		isActive = active;
	}
}
