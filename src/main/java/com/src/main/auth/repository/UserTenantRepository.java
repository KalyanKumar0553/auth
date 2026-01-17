package com.src.main.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.src.main.auth.model.UserTenant;
import com.src.main.auth.model.UserTenantId;

public interface UserTenantRepository extends JpaRepository<UserTenant, UserTenantId> {
	Optional<UserTenant> findByUserIdAndTenantIdAndIsActiveTrue(String userId, String tenantId);
	Optional<UserTenant> findByUserIdAndTenantIdAndIsActiveTrueAndTenantIsActiveTrue(String userId, String tenantId);
}
