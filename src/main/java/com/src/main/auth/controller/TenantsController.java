package com.src.main.auth.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.src.main.auth.dto.common.ApiResponseDto;
import com.src.main.auth.dto.request.CreateTenantRequestDto;
import com.src.main.auth.dto.request.UpdateTenantRequestDto;
import com.src.main.auth.dto.response.TenantSummaryDto;
import com.src.main.auth.service.TenantsService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/tenants")
public class TenantsController {
	private final TenantsService tenantsService;

	public TenantsController(TenantsService tenantsService) {
		this.tenantsService = tenantsService;
	}

	@PostMapping("/create")
	@PreAuthorize("hasAuthority('ROLE_SWAGGER_ADMIN')")
	public ResponseEntity<ApiResponseDto<Void>> create(@RequestBody @Valid CreateTenantRequestDto dto) {
		tenantsService.createTenant(dto);
		return ResponseEntity.ok(ApiResponseDto.ok("Tenant created"));
	}

	@GetMapping("/hashkey")
	public ResponseEntity<ApiResponseDto<String>> generateHashKey() {
		return ResponseEntity.ok(ApiResponseDto.ok("OK", tenantsService.generateShaKey()));
	}

	@GetMapping
	@PreAuthorize("hasAuthority('ROLE_SWAGGER_ADMIN')")
	public ResponseEntity<ApiResponseDto<List<TenantSummaryDto>>> list() {
		return ResponseEntity.ok(ApiResponseDto.ok("OK", tenantsService.listTenants()));
	}

	@DeleteMapping("/{tenantCode}")
	@PreAuthorize("hasAuthority('ROLE_SWAGGER_ADMIN')")
	public ResponseEntity<ApiResponseDto<Void>> remove(@PathVariable String tenantCode) {
		tenantsService.deleteTenant(tenantCode);
		return ResponseEntity.ok(ApiResponseDto.ok("Tenant deleted"));
	}

	@PatchMapping("/{tenantCode}")
	@PreAuthorize("hasAuthority('ROLE_SWAGGER_ADMIN')")
	public ResponseEntity<ApiResponseDto<Void>> update(@PathVariable String tenantCode, @RequestBody UpdateTenantRequestDto dto) {
		tenantsService.updateTenant(tenantCode, dto);
		return ResponseEntity.ok(ApiResponseDto.ok("Tenant updated"));
	}
}
