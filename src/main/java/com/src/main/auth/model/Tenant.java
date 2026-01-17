package com.src.main.auth.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;

@Entity
@Table(name = "tenants")
public class Tenant {
	@Id
	@Column(name = "id", nullable = false, updatable = false)
	private String id;

	@Column(name = "tenant_code", nullable = false, unique = true)
	private String tenantCode;

	@Column(name = "display_name", nullable = false)
	private String displayName;

	@Column(name = "is_active", nullable = false)
	private boolean isActive = true;

	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@Column(name = "updated_at", nullable = false)
	private Instant updatedAt;

	@OneToMany(mappedBy = "tenant")
	private List<UserTenant> userTenants = new ArrayList<>();

	@OneToMany(mappedBy = "tenant")
	private List<TenantRole> roles = new ArrayList<>();

	@OneToMany(mappedBy = "tenant")
	private List<TenantShaKey> shaKeys = new ArrayList<>();

	@OneToMany(mappedBy = "tenant")
	private List<UserTenantVerification> verifications = new ArrayList<>();

	@PrePersist
	public void prePersist() {
		Instant now = Instant.now();
		if (id == null) {
			id = java.util.UUID.randomUUID().toString();
		}
		createdAt = now;
		updatedAt = now;
	}

	@PreUpdate
	public void preUpdate() {
		updatedAt = Instant.now();
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
