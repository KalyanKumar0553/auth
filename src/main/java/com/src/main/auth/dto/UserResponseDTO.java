package com.src.main.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserResponseDTO {
	private Long id;
	private String uuid;
	private String email;
	private String name;
	private boolean emailVerified;
	private String createdAt;
}
