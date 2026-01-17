package com.src.main.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.src.main.auth.model.Tenant;

public interface TenantRepository extends JpaRepository<Tenant, String> {
	Optional<Tenant> findByTenantCode(String tenantCode);
}
