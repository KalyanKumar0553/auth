package com.src.main.auth.model;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

@Entity
@Table(name = "tenant_sha_keys")
public class TenantShaKey {
	@Id
	@Column(name = "id", nullable = false, updatable = false)
	private String id;

	@Column(name = "tenant_id", nullable = false)
	private String tenantId;

	@Column(name = "sha_key", nullable = false)
	private String shaKey;

	@Column(name = "is_active", nullable = false)
	private boolean isActive = true;

	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@Column(name = "rotated_at")
	private Instant rotatedAt;

	@ManyToOne
	@JoinColumn(name = "tenant_id", referencedColumnName = "id", insertable = false, updatable = false)
	private Tenant tenant;

	@PrePersist
	public void prePersist() {
		if (id == null) {
			id = java.util.UUID.randomUUID().toString();
		}
		createdAt = Instant.now();
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getTenantId() {
		return tenantId;
	}

	public void setTenantId(String tenantId) {
		this.tenantId = tenantId;
	}

	public String getShaKey() {
		return shaKey;
	}

	public void setShaKey(String shaKey) {
		this.shaKey = shaKey;
	}

	public boolean isActive() {
		return isActive;
	}

	public void setActive(boolean active) {
		isActive = active;
	}

	public Instant getCreatedAt() {
		return createdAt;
	}

	public Instant getRotatedAt() {
		return rotatedAt;
	}

	public void setRotatedAt(Instant rotatedAt) {
		this.rotatedAt = rotatedAt;
	}
}
