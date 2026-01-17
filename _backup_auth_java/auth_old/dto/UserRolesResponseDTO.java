package com.src.main.auth.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserRolesResponseDTO {
	private String userId;
	private List<String> roles;
	private List<String> permissions;
}
