package com.src.main.auth.controller;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.src.main.common.dto.JSONResponseDTO;
import com.src.main.auth.dto.LoginRequestDTO;
import com.src.main.auth.dto.LoginResponseDTO;
import com.src.main.auth.dto.OTPSentResponseDTO;
import com.src.main.auth.dto.OTPVerificationRequestDTO;
import com.src.main.auth.dto.ResetPasswordRequestDTO;
import com.src.main.auth.dto.ResetPasswordWithOTPResponseDTO;
import com.src.main.auth.dto.SendOTPRequestDTO;
import com.src.main.auth.dto.SignupRequestDTO;
import com.src.main.auth.dto.UserRolesResponseDTO;
import com.src.main.auth.service.AuthService;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Log4j2
@RestController
@AllArgsConstructor
@CrossOrigin
@RequestMapping("/api/auth")
public class AuthController {

	final AuthService authService;

	@PostMapping("/login")
	public ResponseEntity<JSONResponseDTO<LoginResponseDTO>> authenticateUser(@RequestBody @Valid LoginRequestDTO loginRequest,
			HttpServletResponse response) {
		return authService.login(loginRequest, response);
	}

	@PostMapping( value = {"/send-otp","/forgot-password"})
	public ResponseEntity<JSONResponseDTO<OTPSentResponseDTO>> sendOtp(@RequestBody @Valid SendOTPRequestDTO sendOTPRequest) {
		return authService.sendOTP(sendOTPRequest);
	}
	
	@PostMapping("/logout")
	public ResponseEntity<JSONResponseDTO<?>> logout(@RequestHeader("Authorization") String accessToken, @CookieValue(name = "refreshToken", required = false) String refreshToken,HttpServletResponse response) {
		return authService.logout(accessToken,refreshToken,response);
	}
	
	@PostMapping("/reset-password-with-otp")
	public ResponseEntity<JSONResponseDTO<ResetPasswordWithOTPResponseDTO>> resetPasswordWithOTP(
			@RequestBody @Valid ResetPasswordRequestDTO resetPasswordRequest, Authentication authentication) {
		return authService.resetPasswordWithOTP(authentication,resetPasswordRequest);
	}
	
	@PostMapping("/signup")
	public ResponseEntity<JSONResponseDTO<?>> registerUser(@RequestBody @Valid SignupRequestDTO signupRequest)
			throws MessagingException {
		return authService.signup(signupRequest);
	}
	
	
	@PostMapping("/verify-otp")
	public ResponseEntity<JSONResponseDTO<?>> verifyOtp(@RequestBody @Valid OTPVerificationRequestDTO otpVerificationRequest) {
		return authService.verifyOTP(otpVerificationRequest);
	}

	@GetMapping("/roles")
	@PreAuthorize("hasAnyRole('USER','ADMIN')")
	public ResponseEntity<JSONResponseDTO<UserRolesResponseDTO>> getRoles(Principal principal) throws MessagingException {
		return authService.getRoles(principal.getName());
	}


	@PostMapping("/refresh-token")
	public ResponseEntity<JSONResponseDTO<?>> refreshAccessToken(
			@CookieValue(name = "refreshToken", required = false) String refreshToken, HttpServletResponse response) {
		return authService.refreshToken(refreshToken,response);
	}
}
