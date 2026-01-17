package com.src.main.auth.model;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;

@Entity
@Table(name = "user_tenant_verifications")
@IdClass(UserTenantVerificationId.class)
public class UserTenantVerification {
	@jakarta.persistence.Id
	@Column(name = "user_id", nullable = false)
	private String userId;

	@jakarta.persistence.Id
	@Column(name = "tenant_id", nullable = false)
	private String tenantId;

	@Column(name = "email_verified", nullable = false)
	private boolean emailVerified;

	@Column(name = "mobile_verified", nullable = false)
	private boolean mobileVerified;

	@Column(name = "ssn_verified", nullable = false)
	private boolean ssnVerified;

	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@Column(name = "updated_at", nullable = false)
	private Instant updatedAt;

	@ManyToOne
	@JoinColumn(name = "user_id", referencedColumnName = "id", insertable = false, updatable = false)
	private User user;

	@ManyToOne
	@JoinColumn(name = "tenant_id", referencedColumnName = "id", insertable = false, updatable = false)
	private Tenant tenant;

	@PrePersist
	public void prePersist() {
		Instant now = Instant.now();
		createdAt = now;
		updatedAt = now;
	}

	@PreUpdate
	public void preUpdate() {
		updatedAt = Instant.now();
	}

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

	public boolean isEmailVerified() {
		return emailVerified;
	}

	public void setEmailVerified(boolean emailVerified) {
		this.emailVerified = emailVerified;
	}

	public boolean isMobileVerified() {
		return mobileVerified;
	}

	public void setMobileVerified(boolean mobileVerified) {
		this.mobileVerified = mobileVerified;
	}

	public boolean isSsnVerified() {
		return ssnVerified;
	}

	public void setSsnVerified(boolean ssnVerified) {
		this.ssnVerified = ssnVerified;
	}
}
