package com.src.main.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.src.main.auth.dto.common.ApiResponseDto;
import com.src.main.auth.dto.request.SwaggerPasswordRequestDto;
import com.src.main.auth.dto.response.AccessTokenResponseDto;
import com.src.main.auth.dto.response.RolesResponseDto;
import com.src.main.auth.service.AuthService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/admin")
public class SwaggerController {
	private final AuthService authService;

	public SwaggerController(AuthService authService) {
		this.authService = authService;
	}

	@PostMapping("/swagger/reset-password")
	@PreAuthorize("hasAuthority('ROLE_SWAGGER_ADMIN')")
	public ResponseEntity<ApiResponseDto<Void>> updateSwaggerPassword(@RequestBody @Valid SwaggerPasswordRequestDto dto) {
		authService.updateSwaggerPassword(dto.getUsername(), dto.getPassword());
		return ResponseEntity.ok(ApiResponseDto.ok("Swagger password updated"));
	}

	@PostMapping("/swagger/token")
	@PreAuthorize("isAuthenticated()")
	@Operation(summary = "Return the caller's JWT access token", security = @SecurityRequirement(name = "bearerAuth"))
	public ResponseEntity<ApiResponseDto<AccessTokenResponseDto>> swaggerToken(Authentication authentication) {
		String token = null;
		if (authentication != null && authentication.getCredentials() instanceof String credentials) {
			token = credentials;
		}
		if (token == null || token.isBlank()) {
			throw new IllegalArgumentException("Missing bearer token");
		}
		return ResponseEntity.ok(ApiResponseDto.ok("OK", new AccessTokenResponseDto(token)));
	}

	@GetMapping("/swagger/roles")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponseDto<RolesResponseDto>> swaggerRoles(org.springframework.security.core.Authentication auth) {
		return ResponseEntity.ok(ApiResponseDto.ok("OK", new RolesResponseDto(auth.getAuthorities().stream().map(a -> a.getAuthority()).toList())));
	}
}
