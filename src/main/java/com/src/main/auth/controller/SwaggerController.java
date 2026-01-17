package com.src.main.auth.controller;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.src.main.auth.dto.common.ApiResponseDto;
import com.src.main.auth.dto.request.SwaggerPasswordRequestDto;
import com.src.main.auth.dto.response.AccessTokenResponseDto;
import com.src.main.auth.dto.response.RolesResponseDto;
import com.src.main.auth.service.AuthService;

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
	public ResponseEntity<ApiResponseDto<AccessTokenResponseDto>> swaggerToken(@RequestHeader("Authorization") String authorization) {
		if (authorization == null || !authorization.startsWith("Basic ")) {
			throw new IllegalArgumentException("Missing basic auth");
		}
		String decoded = new String(Base64.getDecoder().decode(authorization.substring(6)), StandardCharsets.UTF_8);
		int sep = decoded.indexOf(':');
		if (sep < 0) {
			throw new IllegalArgumentException("Invalid basic auth");
		}
		String username = decoded.substring(0, sep);
		String password = decoded.substring(sep + 1);
		String token = authService.issueSwaggerToken(username, password);
		return ResponseEntity.ok(ApiResponseDto.ok("OK", new AccessTokenResponseDto(token)));
	}

	@GetMapping("/swagger/roles")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponseDto<RolesResponseDto>> swaggerRoles(org.springframework.security.core.Authentication auth) {
		return ResponseEntity.ok(ApiResponseDto.ok("OK", new RolesResponseDto(auth.getAuthorities().stream().map(a -> a.getAuthority()).toList())));
	}
}
