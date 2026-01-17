package com.src.main.auth.dto.request;

import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;

public class UpdateTenantRolesDto {
	@NotEmpty
	@Valid
	private List<TenantRoleInputDto> roles;

	public List<TenantRoleInputDto> getRoles() {
		return roles;
	}

	public void setRoles(List<TenantRoleInputDto> roles) {
		this.roles = roles;
	}
}
