package com.src.main.auth.dto.request;

import java.util.List;

import jakarta.validation.constraints.NotEmpty;

public class UpdateUserTenantRolesDto {
	@NotEmpty
	private List<String> roles;

	public List<String> getRoles() {
		return roles;
	}

	public void setRoles(List<String> roles) {
		this.roles = roles;
	}
}
