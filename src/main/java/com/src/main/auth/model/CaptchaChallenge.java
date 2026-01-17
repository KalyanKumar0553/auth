package com.src.main.auth.model;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

@Entity
@Table(name = "captcha_challenges")
public class CaptchaChallenge {
	@Id
	@Column(name = "id", nullable = false, updatable = false)
	private String id;

	@Column(name = "answer_hash", nullable = false)
	private String answerHash;

	@Column(name = "expires_at", nullable = false)
	private Instant expiresAt;

	@Column(name = "used", nullable = false)
	private boolean used;

	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

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

	public String getAnswerHash() {
		return answerHash;
	}

	public void setAnswerHash(String answerHash) {
		this.answerHash = answerHash;
	}

	public Instant getExpiresAt() {
		return expiresAt;
	}

	public void setExpiresAt(Instant expiresAt) {
		this.expiresAt = expiresAt;
	}

	public boolean isUsed() {
		return used;
	}

	public void setUsed(boolean used) {
		this.used = used;
	}

	public Instant getCreatedAt() {
		return createdAt;
	}
}
