package com.src.main.auth.dto.response;

import java.util.List;

public class RolesResponseDto {
	private List<String> roles;

	public RolesResponseDto() {}

	public RolesResponseDto(List<String> roles) {
		this.roles = roles;
	}

	public List<String> getRoles() {
		return roles;
	}

	public void setRoles(List<String> roles) {
		this.roles = roles;
	}
}
