package com.src.main.auth.service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.src.main.auth.dto.request.CreateTenantRequestDto;
import com.src.main.auth.dto.request.UpdateTenantRequestDto;
import com.src.main.auth.dto.response.TenantSummaryDto;
import com.src.main.auth.model.Tenant;
import com.src.main.auth.model.TenantRole;
import com.src.main.auth.model.TenantShaKey;
import com.src.main.auth.repository.TenantRepository;
import com.src.main.auth.repository.TenantRoleRepository;
import com.src.main.auth.repository.TenantShaKeyRepository;

@Service
public class TenantsService {
	private final TenantRepository tenantRepository;
	private final TenantShaKeyRepository shaKeyRepository;
	private final TenantRoleRepository tenantRoleRepository;
	private final SecureRandom random = new SecureRandom();

	public TenantsService(
			TenantRepository tenantRepository,
			TenantShaKeyRepository shaKeyRepository,
			TenantRoleRepository tenantRoleRepository) {
		this.tenantRepository = tenantRepository;
		this.shaKeyRepository = shaKeyRepository;
		this.tenantRoleRepository = tenantRoleRepository;
	}

	public List<TenantSummaryDto> listTenants() {
		return tenantRepository.findAll().stream()
				.sorted((a, b) -> a.getTenantCode().compareToIgnoreCase(b.getTenantCode()))
				.map(t -> new TenantSummaryDto(t.getId(), t.getTenantCode(), t.getDisplayName(), t.isActive()))
				.collect(Collectors.toList());
	}

	@Transactional
	public void deleteTenant(String tenantCode) {
		Tenant tenant = tenantRepository.findByTenantCode(tenantCode)
				.orElseThrow(() -> new IllegalArgumentException("Tenant not found"));
		tenantRepository.delete(tenant);
	}

	@Transactional
	public void updateTenant(String tenantCode, UpdateTenantRequestDto dto) {
		Tenant tenant = tenantRepository.findByTenantCode(tenantCode)
				.orElseThrow(() -> new IllegalArgumentException("Tenant not found"));
		if (dto.getTenantCode() != null) {
			throw new IllegalArgumentException("tenantCode cannot be updated");
		}
		if (dto.getShaKey() != null) {
			throw new IllegalArgumentException("shaKey cannot be updated via tenant patch");
		}
		if (dto.getDisplayName() != null) {
			tenant.setDisplayName(dto.getDisplayName());
		}
		if (dto.getIsActive() != null) {
			tenant.setActive(dto.getIsActive());
		}
		tenantRepository.save(tenant);
	}

	@Transactional
	public void createTenant(CreateTenantRequestDto dto) {
		if (tenantRepository.findByTenantCode(dto.getTenantCode()).isPresent()) {
			throw new IllegalArgumentException("Tenant code already exists");
		}
		if (shaKeyRepository.existsByShaKey(dto.getShaKey())) {
			throw new IllegalArgumentException("SHA key already in use by another tenant");
		}

		Tenant tenant = new Tenant();
		tenant.setTenantCode(dto.getTenantCode());
		tenant.setDisplayName(dto.getDisplayName());
		tenant.setActive(dto.getIsActive() == null ? true : dto.getIsActive());
		tenantRepository.save(tenant);

		TenantShaKey shaKey = new TenantShaKey();
		shaKey.setTenantId(tenant.getId());
		shaKey.setShaKey(dto.getShaKey());
		shaKey.setActive(true);
		shaKeyRepository.save(shaKey);

		TenantRole userRole = new TenantRole();
		userRole.setTenantId(tenant.getId());
		userRole.setName("ROLE_USER");
		userRole.setActive(true);
		tenantRoleRepository.save(userRole);

		TenantRole adminRole = new TenantRole();
		adminRole.setTenantId(tenant.getId());
		adminRole.setName("ROLE_ADMIN");
		adminRole.setActive(true);
		tenantRoleRepository.save(adminRole);
	}

	public String generateShaKey() {
		byte[] bytes = new byte[32];
		random.nextBytes(bytes);
		return Base64.getEncoder().encodeToString(bytes);
	}
}
