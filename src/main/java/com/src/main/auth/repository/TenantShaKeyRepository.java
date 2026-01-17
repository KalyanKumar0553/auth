package com.src.main.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.src.main.auth.model.TenantShaKey;

public interface TenantShaKeyRepository extends JpaRepository<TenantShaKey, String> {
	Optional<TenantShaKey> findFirstByTenantIdAndIsActiveTrueOrderByCreatedAtDesc(String tenantId);
	boolean existsByShaKey(String shaKey);
}
