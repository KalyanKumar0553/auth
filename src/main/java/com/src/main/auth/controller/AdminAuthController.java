package com.src.main.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.src.main.auth.dto.common.ApiResponseDto;
import com.src.main.auth.dto.request.LoginRequestDto;
import com.src.main.auth.dto.response.TokenPairResponseDto;
import com.src.main.auth.service.AuthService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/admin/auth")
public class AdminAuthController {
	private final AuthService authService;

	public AdminAuthController(AuthService authService) {
		this.authService = authService;
	}

	@PostMapping("/login")
	public ResponseEntity<ApiResponseDto<TokenPairResponseDto>> login(@RequestBody @Valid LoginRequestDto dto) {
		String token = authService.issueSwaggerToken(dto.getIdentifier(), dto.getPassword());
		return ResponseEntity.ok(ApiResponseDto.ok("Authenticated", new TokenPairResponseDto(token, null)));
	}
}
