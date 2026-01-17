package com.src.main.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.src.main.auth.model.UserTenantVerification;
import com.src.main.auth.model.UserTenantVerificationId;

public interface UserTenantVerificationRepository extends JpaRepository<UserTenantVerification, UserTenantVerificationId> {
	Optional<UserTenantVerification> findByUserIdAndTenantId(String userId, String tenantId);
}
