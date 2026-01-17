package com.src.main.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.src.main.auth.dto.common.ApiResponseDto;
import com.src.main.auth.dto.request.AddTenantAdminDto;
import com.src.main.auth.dto.request.UpdateTenantRolesDto;
import com.src.main.auth.dto.request.UpdateTenantVerificationDto;
import com.src.main.auth.dto.request.UpdateUserTenantRolesDto;
import com.src.main.auth.service.TenantDataService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/tenant")
public class TenantDataController {
	private final TenantDataService tenantDataService;

	public TenantDataController(TenantDataService tenantDataService) {
		this.tenantDataService = tenantDataService;
	}

	@GetMapping("/settings/count")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponseDto<Long>> countSettings() {
		long count = tenantDataService.countSettings();
		return ResponseEntity.ok(ApiResponseDto.ok("OK", count));
	}

	@PutMapping("/roles")
	@PreAuthorize("hasAuthority('ROLE_SWAGGER_ADMIN')")
	public ResponseEntity<ApiResponseDto<Void>> updateTenantRoles(@RequestBody @Valid UpdateTenantRolesDto dto) {
		tenantDataService.updateTenantRoles(dto);
		return ResponseEntity.ok(ApiResponseDto.ok("Tenant roles updated"));
	}

	@PutMapping("/users/{userId}/roles")
	@PreAuthorize("hasAuthority('ROLE_SWAGGER_ADMIN')")
	public ResponseEntity<ApiResponseDto<Void>> updateUserRoles(
			@PathVariable String userId,
			@RequestBody @Valid UpdateUserTenantRolesDto dto) {
		tenantDataService.updateUserRoles(userId, dto.getRoles());
		return ResponseEntity.ok(ApiResponseDto.ok("User roles updated"));
	}

	@PutMapping("/admins")
	@PreAuthorize("hasAuthority('ROLE_SWAGGER_ADMIN')")
	public ResponseEntity<ApiResponseDto<Void>> addTenantAdmin(@RequestBody @Valid AddTenantAdminDto dto) {
		tenantDataService.addTenantAdmin(dto.getIdentifier());
		return ResponseEntity.ok(ApiResponseDto.ok("Tenant admin added"));
	}

	@PutMapping("/users/verify")
	@PreAuthorize("hasAuthority('ROLE_SWAGGER_ADMIN')")
	public ResponseEntity<ApiResponseDto<Void>> verifyUser(@RequestBody @Valid UpdateTenantVerificationDto dto) {
		tenantDataService.updateTenantVerification(dto);
		return ResponseEntity.ok(ApiResponseDto.ok("User verification updated"));
	}
}
