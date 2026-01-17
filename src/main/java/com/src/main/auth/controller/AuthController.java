package com.src.main.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.src.main.auth.dto.common.ApiResponseDto;
import com.src.main.auth.dto.request.AppleOauthRequestDto;
import com.src.main.auth.dto.request.ForgotPasswordRequestDto;
import com.src.main.auth.dto.request.GoogleOauthRequestDto;
import com.src.main.auth.dto.request.LoginRequestDto;
import com.src.main.auth.dto.request.LogoutRequestDto;
import com.src.main.auth.dto.request.OtpGenerateRequestDto;
import com.src.main.auth.dto.request.OtpVerifyRequestDto;
import com.src.main.auth.dto.request.RefreshRequestDto;
import com.src.main.auth.dto.request.ResetPasswordRequestDto;
import com.src.main.auth.dto.request.SignupRequestDto;
import com.src.main.auth.dto.request.TokenValidateRequestDto;
import com.src.main.auth.dto.response.CaptchaResponseDto;
import com.src.main.auth.dto.response.RolesResponseDto;
import com.src.main.auth.dto.response.TokenPairResponseDto;
import com.src.main.auth.service.AuthService;
import com.src.main.auth.service.CaptchaService;
import com.src.main.auth.service.OauthService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
	private final AuthService authService;
	private final OauthService oauthService;
	private final CaptchaService captchaService;

	public AuthController(AuthService authService, OauthService oauthService, CaptchaService captchaService) {
		this.authService = authService;
		this.oauthService = oauthService;
		this.captchaService = captchaService;
	}

	@GetMapping("/captcha")
	public ResponseEntity<ApiResponseDto<CaptchaResponseDto>> captcha() {
		var captcha = captchaService.generate();
		return ResponseEntity.ok(ApiResponseDto.ok("OK", new CaptchaResponseDto(captcha.captchaId(), captcha.imageBase64())));
	}

	@PostMapping("/signup")
	public ResponseEntity<ApiResponseDto<Void>> signup(@RequestBody @Valid SignupRequestDto dto) {
		authService.signup(dto.getIdentifier(), dto.getPassword(), dto.getCaptchaId(), dto.getCaptchaText());
		return ResponseEntity.ok(ApiResponseDto.ok("Signup created. Please verify OTP."));
	}

	@GetMapping("/identifier/exists")
	public ResponseEntity<ApiResponseDto<Boolean>> exists(@RequestParam("value") String value) {
		return ResponseEntity.ok(ApiResponseDto.ok("OK", authService.identifierExists(value)));
	}

	@PostMapping("/otp/generate")
	public ResponseEntity<ApiResponseDto<Void>> generateOtp(@RequestBody @Valid OtpGenerateRequestDto dto) {
		authService.generateOtpForSignup(dto.getIdentifier(), dto.getCaptchaId(), dto.getCaptchaText());
		return ResponseEntity.ok(ApiResponseDto.ok("OTP sent"));
	}

	@PostMapping("/otp/verify")
	public ResponseEntity<ApiResponseDto<Void>> verifyOtp(@RequestBody @Valid OtpVerifyRequestDto dto) {
		authService.verifySignupOtp(dto.getIdentifier(), dto.getOtp());
		return ResponseEntity.ok(ApiResponseDto.ok("Account verified"));
	}

	@PostMapping("/password/forgot")
	public ResponseEntity<ApiResponseDto<Void>> forgot(@RequestBody @Valid ForgotPasswordRequestDto dto) {
		authService.forgotPassword(dto.getIdentifier(), dto.getCaptchaId(), dto.getCaptchaText());
		return ResponseEntity.ok(ApiResponseDto.ok("OTP sent"));
	}

	@PostMapping("/password/reset")
	public ResponseEntity<ApiResponseDto<Void>> reset(@RequestBody @Valid ResetPasswordRequestDto dto) {
		authService.resetPassword(dto.getIdentifier(), dto.getOtp(), dto.getNewPassword());
		return ResponseEntity.ok(ApiResponseDto.ok("Password reset successful"));
	}

	@PostMapping("/login")
	public ResponseEntity<ApiResponseDto<TokenPairResponseDto>> login(@RequestBody @Valid LoginRequestDto dto) {
		return ResponseEntity.ok(ApiResponseDto.ok("Authenticated", authService.login(dto.getIdentifier(), dto.getPassword())));
	}

	@PostMapping("/oauth/google")
	public ResponseEntity<ApiResponseDto<TokenPairResponseDto>> google(@RequestBody @Valid GoogleOauthRequestDto dto) {
		String email = oauthService.verifyGoogleIdToken(dto.getIdToken());
		String userId = oauthService.upsertOauthUser(email);
		return ResponseEntity.ok(ApiResponseDto.ok("Authenticated", authService.loginWithUserId(userId)));
	}

	@PostMapping("/oauth/apple")
	public ResponseEntity<ApiResponseDto<TokenPairResponseDto>> apple(@RequestBody @Valid AppleOauthRequestDto dto) {
		String email = oauthService.verifyAppleIdentityToken(dto.getIdentityToken());
		String userId = oauthService.upsertOauthUser(email);
		return ResponseEntity.ok(ApiResponseDto.ok("Authenticated", authService.loginWithUserId(userId)));
	}

	@PostMapping("/token/refresh")
	public ResponseEntity<ApiResponseDto<TokenPairResponseDto>> refresh(@RequestBody @Valid RefreshRequestDto dto) {
		return ResponseEntity.ok(ApiResponseDto.ok("Refreshed", authService.refresh(dto.getRefreshToken())));
	}

	@PostMapping("/token/validate")
	public ResponseEntity<ApiResponseDto<Boolean>> validate(@RequestBody @Valid TokenValidateRequestDto dto) {
		return ResponseEntity.ok(ApiResponseDto.ok("OK", authService.validate(dto.getToken())));
	}

	@PostMapping("/logout")
	public ResponseEntity<ApiResponseDto<Void>> logout(@RequestBody @Valid LogoutRequestDto dto) {
		authService.logout(dto.getRefreshToken());
		return ResponseEntity.ok(ApiResponseDto.ok("Logged out"));
	}

	@GetMapping("/roles")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponseDto<RolesResponseDto>> roles(org.springframework.security.core.Authentication auth) {
		String userId = auth.getName();
		return ResponseEntity.ok(ApiResponseDto.ok("OK", new RolesResponseDto(authService.getUserRoles(userId))));
	}
}
