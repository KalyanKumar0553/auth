package com.src.main.auth.service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.src.main.auth.dto.request.UpdateTenantRolesDto;
import com.src.main.auth.dto.request.UpdateTenantVerificationDto;
import com.src.main.auth.model.TenantRole;
import com.src.main.auth.model.User;
import com.src.main.auth.model.UserTenant;
import com.src.main.auth.model.UserTenantRole;
import com.src.main.auth.model.UserTenantVerification;
import com.src.main.auth.repository.SettingRepository;
import com.src.main.auth.repository.TenantRoleRepository;
import com.src.main.auth.repository.UserRepository;
import com.src.main.auth.repository.UserTenantRepository;
import com.src.main.auth.repository.UserTenantRoleRepository;
import com.src.main.auth.repository.UserTenantVerificationRepository;
import com.src.main.auth.tenant.TenantConfig;
import com.src.main.auth.tenant.TenantContextService;
import com.src.main.auth.util.IdentifierUtils;

@Service
public class TenantDataService {
	private final SettingRepository settingRepository;
	private final TenantRoleRepository tenantRoleRepository;
	private final UserRepository userRepository;
	private final UserTenantRepository userTenantRepository;
	private final UserTenantRoleRepository userTenantRoleRepository;
	private final UserTenantVerificationRepository verificationRepository;
	private final TenantContextService tenantContext;

	public TenantDataService(
			SettingRepository settingRepository,
			TenantRoleRepository tenantRoleRepository,
			UserRepository userRepository,
			UserTenantRepository userTenantRepository,
			UserTenantRoleRepository userTenantRoleRepository,
			UserTenantVerificationRepository verificationRepository,
			TenantContextService tenantContext) {
		this.settingRepository = settingRepository;
		this.tenantRoleRepository = tenantRoleRepository;
		this.userRepository = userRepository;
		this.userTenantRepository = userTenantRepository;
		this.userTenantRoleRepository = userTenantRoleRepository;
		this.verificationRepository = verificationRepository;
		this.tenantContext = tenantContext;
	}

	public long countSettings() {
		return settingRepository.count();
	}

	@Transactional
	public void updateTenantRoles(UpdateTenantRolesDto dto) {
		TenantConfig tenant = getTenant();
		if (dto.getRoles() == null || dto.getRoles().isEmpty()) {
			throw new IllegalArgumentException("Roles are required");
		}
		for (var roleDto : dto.getRoles()) {
			String name = roleDto.getName().trim().toUpperCase();
			if (name.isEmpty()) throw new IllegalArgumentException("Role name is required");
			if ("ROLE_SWAGGER_ADMIN".equals(name)) {
				throw new IllegalArgumentException("ROLE_SWAGGER_ADMIN cannot be managed as a tenant role");
			}
			boolean isActive = roleDto.getIsActive() == null || roleDto.getIsActive();
			if ("ROLE_USER".equals(name)) isActive = true;
			TenantRole role = tenantRoleRepository.findByTenantIdAndName(tenant.getId(), name)
					.orElseGet(() -> {
						TenantRole r = new TenantRole();
						r.setTenantId(tenant.getId());
						r.setName(name);
						return r;
					});
			role.setActive(isActive);
			tenantRoleRepository.save(role);
		}

		if (tenantRoleRepository.findByTenantIdAndName(tenant.getId(), "ROLE_USER").isEmpty()) {
			TenantRole role = new TenantRole();
			role.setTenantId(tenant.getId());
			role.setName("ROLE_USER");
			role.setActive(true);
			tenantRoleRepository.save(role);
		}
	}

	@Transactional
	public void updateUserRoles(String userId, List<String> roles) {
		TenantConfig tenant = getTenant();
		UserTenant membership = userTenantRepository
				.findByUserIdAndTenantIdAndIsActiveTrue(userId, tenant.getId())
				.orElseThrow(() -> new IllegalArgumentException("User is not a member of this tenant"));

		UserTenantVerification verification = verificationRepository
				.findByUserIdAndTenantId(userId, tenant.getId())
				.orElseThrow(() -> new IllegalArgumentException("User is not verified for this tenant"));
		if (!verification.isEmailVerified() && !verification.isMobileVerified() && !verification.isSsnVerified()) {
			throw new IllegalArgumentException("User is not verified for this tenant");
		}

		Set<String> normalized = roles.stream()
				.map(r -> r.trim().toUpperCase())
				.filter(r -> !r.isBlank())
				.collect(Collectors.toSet());
		normalized.add("ROLE_USER");
		List<TenantRole> tenantRoles = tenantRoleRepository
				.findByTenantIdAndNameInAndIsActiveTrue(tenant.getId(), normalized.stream().toList());
		if (tenantRoles.size() != normalized.size()) {
			Set<String> existing = tenantRoles.stream().map(TenantRole::getName).collect(Collectors.toSet());
			List<String> missing = normalized.stream().filter(n -> !existing.contains(n)).toList();
			throw new IllegalArgumentException("Unknown or inactive roles: " + String.join(", ", missing));
		}

		userTenantRoleRepository.deleteByUserIdAndTenantRoleTenantId(userId, tenant.getId());
		for (TenantRole role : tenantRoles) {
			UserTenantRole assignment = new UserTenantRole();
			assignment.setUserId(userId);
			assignment.setTenantRoleId(role.getId());
			userTenantRoleRepository.save(assignment);
		}
	}

	@Transactional
	public void addTenantAdmin(String identifier) {
		TenantConfig tenant = getTenant();
		String id = IdentifierUtils.normalizeIdentifier(identifier);
		User user = userRepository.findByIdentifier(id).orElseThrow(() -> new IllegalArgumentException("User not found"));
		userTenantRepository.findByUserIdAndTenantIdAndIsActiveTrue(user.getId(), tenant.getId())
				.orElseThrow(() -> new IllegalArgumentException("User is not a member of this tenant"));

		UserTenantVerification verification = verificationRepository
				.findByUserIdAndTenantId(user.getId(), tenant.getId())
				.orElseThrow(() -> new IllegalArgumentException("User is not verified for this tenant"));
		if (!verification.isEmailVerified() && !verification.isMobileVerified() && !verification.isSsnVerified()) {
			throw new IllegalArgumentException("User is not verified for this tenant");
		}

		TenantRole adminRole = tenantRoleRepository
				.findByTenantIdAndName(tenant.getId(), "ROLE_ADMIN")
				.orElseThrow(() -> new IllegalArgumentException("ROLE_ADMIN is not configured for this tenant"));

		UserTenantRole assignment = new UserTenantRole();
		assignment.setUserId(user.getId());
		assignment.setTenantRoleId(adminRole.getId());
		userTenantRoleRepository.save(assignment);
	}

	@Transactional
	public void updateTenantVerification(UpdateTenantVerificationDto dto) {
		TenantConfig tenant = getTenant();
		String id = IdentifierUtils.normalizeIdentifier(dto.getIdentifier());
		User user = userRepository.findByIdentifier(id).orElseThrow(() -> new IllegalArgumentException("User not found"));
		userTenantRepository.findByUserIdAndTenantIdAndIsActiveTrue(user.getId(), tenant.getId())
				.orElseThrow(() -> new IllegalArgumentException("User is not a member of this tenant"));

		if (dto.getEmailVerified() == null && dto.getMobileVerified() == null && dto.getSsnVerified() == null) {
			throw new IllegalArgumentException("At least one verification flag is required");
		}

		UserTenantVerification verification = verificationRepository
				.findByUserIdAndTenantId(user.getId(), tenant.getId())
				.orElseGet(() -> {
					UserTenantVerification v = new UserTenantVerification();
					v.setUserId(user.getId());
					v.setTenantId(tenant.getId());
					return v;
				});
		if (dto.getEmailVerified() != null) {
			verification.setEmailVerified(dto.getEmailVerified());
		}
		if (dto.getMobileVerified() != null) {
			verification.setMobileVerified(dto.getMobileVerified());
		}
		if (dto.getSsnVerified() != null) {
			verification.setSsnVerified(dto.getSsnVerified());
		}
		verificationRepository.save(verification);
	}

	private TenantConfig getTenant() {
		TenantConfig tenant = tenantContext.getTenant();
		if (tenant == null) {
			throw new IllegalArgumentException("Tenant context is not set");
		}
		return tenant;
	}
}
