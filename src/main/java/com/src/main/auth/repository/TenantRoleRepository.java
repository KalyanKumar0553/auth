package com.src.main.auth.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.src.main.auth.model.TenantRole;

public interface TenantRoleRepository extends JpaRepository<TenantRole, String> {
	Optional<TenantRole> findByTenantIdAndName(String tenantId, String name);
	List<TenantRole> findByTenantIdAndNameInAndIsActiveTrue(String tenantId, List<String> names);
}
