package com.src.main.auth.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.src.main.auth.model.UserTenantRole;
import com.src.main.auth.model.UserTenantRoleId;

public interface UserTenantRoleRepository extends JpaRepository<UserTenantRole, UserTenantRoleId> {
	List<UserTenantRole> findByUserIdAndTenantRoleTenantIdAndTenantRoleIsActiveTrue(String userId, String tenantId);
	void deleteByUserIdAndTenantRoleTenantId(String userId, String tenantId);
}
