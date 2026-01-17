package com.src.main.auth.service;

import java.time.Duration;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.thymeleaf.context.Context;

import com.src.main.auth.config.JWTTokenProvider;
import com.src.main.auth.config.OtpConfig;
import com.src.main.common.dto.JSONResponseDTO;
import com.src.main.auth.dto.LoginRequestDTO;
import com.src.main.auth.dto.LoginResponseDTO;
import com.src.main.auth.dto.OTPSentResponseDTO;
import com.src.main.auth.dto.OTPVerificationRequestDTO;
import com.src.main.auth.dto.ResetPasswordRequestDTO;
import com.src.main.auth.dto.ResetPasswordWithOTPResponseDTO;
import com.src.main.auth.dto.SendOTPRequestDTO;
import com.src.main.auth.dto.SignupRequestDTO;
import com.src.main.auth.dto.SignupResponseDTO;
import com.src.main.auth.dto.UserResponseDTO;
import com.src.main.auth.dto.UserRolesResponseDTO;
import com.src.main.auth.exception.UserNotFoundException;
import com.src.main.auth.model.UserInfo;
import com.src.main.auth.repository.RolesPermissionsRepository;
import com.src.main.auth.transformer.UserInfoTransformer;
import com.src.main.common.util.AppUtils;
import com.src.main.auth.util.PasswordUtil;
import com.src.main.common.util.RequestStatus;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class AuthService {

	final UserInfoTransformer userInfoTransformer;

	final JWTTokenProvider jwtTokenProvider;

	final AuthenticationManager authenticationManager;

	final JWTTokenProvider tokenProvider;

	final UserDetailsServiceImpl userService;
	
	final RolesPermissionsRepository permissionsRepo;

	final PasswordEncoder passwordEncoder;
	
	final OtpConfig otpConfig;

	public ResponseEntity<JSONResponseDTO<LoginResponseDTO>> login(LoginRequestDTO loginRequest,
			HttpServletResponse response) {
		UserInfo user = userService.validateAndGetIfUserEnabled(loginRequest);
		String hashPassword = PasswordUtil.hashPassword(loginRequest.getPassword(), user.getSalt());
		String encodedPassword = passwordEncoder.encode(hashPassword);
		if (!passwordEncoder.matches(hashPassword, encodedPassword)) {
			throw new UserNotFoundException(RequestStatus.BAD_CREDENTIALS);
		}
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(user.getUsername(),
				hashPassword, userService.getAuthorities(user.getUuid()));
		Authentication authentication = authenticationManager.authenticate(authToken);

		String accessToken = tokenProvider.generateAccessToken(authentication, user.getUuid());
		String refreshToken = tokenProvider.generateRefreshToken(user.getUsername(), user.getUuid());

		ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken).httpOnly(true).secure(true)
				.sameSite("Strict").path("/api/auth/refresh-token").maxAge(Duration.ofDays(7)).build();

		response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
		response.addHeader("Authorization", "Bearer " + accessToken);
		SecurityContextHolder.getContext().setAuthentication(authToken);

		Date expiresAt = tokenProvider.extractExpiration(accessToken);
		DateTimeFormatter formatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
		String formatted = expiresAt.toInstant().atZone(ZoneId.systemDefault()).format(formatter);

		UserResponseDTO userResponse = UserResponseDTO.builder().id(user.getId()).uuid(user.getUuid())
				.email(user.getEmail()).name(user.getFullName()).emailVerified(user.isEnabled()).createdAt(formatted)
				.build();

		LoginResponseDTO logjResponse = LoginResponseDTO.builder().accessToken(accessToken).refreshToken(refreshToken)
				.user(userResponse).build();

		return ResponseEntity.ok(AppUtils.getJSONObject(logjResponse, RequestStatus.LOGIN_SUCCESS.getDescription()));

	}

	public ResponseEntity<JSONResponseDTO<OTPSentResponseDTO>> sendOTP(SendOTPRequestDTO sendOTPRequest) {
		String username = sendOTPRequest.getEmail();
		UserInfo user = userService.findUserByUsername(username)
				.orElseThrow(() -> new UserNotFoundException(RequestStatus.USER_NOT_FOUND));
		Context context = new Context();
		context.setVariable("otp", userService.generateOtp());
		boolean otpSent = userService.sendOTP(user, context);
		OTPSentResponseDTO response = OTPSentResponseDTO.builder()
				.expiresIn(Duration.ofMinutes(otpConfig.getOtpValiditiyMinutes()).toSeconds()).otpSent(otpSent).build();
		return ResponseEntity.ok(AppUtils.getJSONObject(response, RequestStatus.OTP_SENT_SUCCESS.getDescription()));
	}

	public ResponseEntity<JSONResponseDTO<ResetPasswordWithOTPResponseDTO>> resetPasswordWithOTP(
			Authentication authentication, ResetPasswordRequestDTO resetPasswordRequest) {
		UserInfo user = userService.findUserByUsername(resetPasswordRequest.getEmail())
				.orElseThrow(() -> new UserNotFoundException(RequestStatus.USER_NOT_FOUND));
		userService.resetPasswordWithOTP(user, resetPasswordRequest.getOtp(), resetPasswordRequest.getPassword(),
				passwordEncoder);
		ResetPasswordWithOTPResponseDTO response = ResetPasswordWithOTPResponseDTO.builder().reset(true).build();
		return ResponseEntity
				.ok(AppUtils.getJSONObject(response, RequestStatus.PASSWORD_RESET_SUCCESS.getDescription()));
	}

	public ResponseEntity<JSONResponseDTO<?>> logout(String accessToken, String refreshToken,
			HttpServletResponse response) {
		if (refreshToken != null) {
			jwtTokenProvider.invalidateRefreshToken(refreshToken);
		}
		if (StringUtils.hasText(accessToken) && accessToken.startsWith("Bearer ")) {
			accessToken = accessToken.substring(7);
			jwtTokenProvider.invalidateToken(accessToken);
		}
		ResponseCookie clearCookie = ResponseCookie.from("refreshToken", "").httpOnly(true).secure(true)
				.path("/auth/refresh-token").maxAge(0).build();
		response.addHeader(HttpHeaders.SET_COOKIE, clearCookie.toString());
		return ResponseEntity.ok(AppUtils.getJSONObject(null, RequestStatus.LOGOUT_SUCCESS.getDescription()));
	}

	public ResponseEntity<JSONResponseDTO<?>> verifyOTP(OTPVerificationRequestDTO otpVerificationRequest) {
		UserInfo user = userService.findUserByUsername(otpVerificationRequest.getEmail())
				.orElseThrow(() -> new UserNotFoundException(RequestStatus.USER_NOT_FOUND));
		if (user.isEnabled()) {
			return ResponseEntity
					.internalServerError().body(AppUtils.getJSONObject(null,RequestStatus.USER_ALREADY_VERIFIED_ERROR.getDescription()));
		}
		userService.verifyOtp(otpVerificationRequest.getEmail(), otpVerificationRequest.getOtp());
		return ResponseEntity
				.ok(AppUtils.getJSONObject(null,RequestStatus.OTP_VERIFICATION_SUCCESS.getDescription()));
	}
	
	public ResponseEntity<JSONResponseDTO<?>> signup(SignupRequestDTO signupRequest) {
		userService.checkDuplicateUser(signupRequest);
		UserInfo userInfo = userInfoTransformer.fromSignupRequestDTO(signupRequest);
		userInfo = userService.saveUser(userInfo, passwordEncoder);
		SignupResponseDTO response = SignupResponseDTO.builder().email(userInfo.getEmail()).userId(userInfo.getUuid())
				.otpSent(true).otpExpiresIn(Duration.ofMinutes(otpConfig.getOtpValiditiyMinutes()).toSeconds()).build();
		return ResponseEntity
				.ok(AppUtils.getJSONObject(response, String.format(RequestStatus.SIGNUP_SUCCESS.getDescription(),userInfo.getEmail())));
	}

	public ResponseEntity<JSONResponseDTO<?>> refreshToken(String refreshToken, HttpServletResponse response) {
		if (refreshToken == null || !tokenProvider.validateToken(refreshToken)) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
					JSONResponseDTO.builder().isError(false).message("Invalid or expired refresh token").build());
		}

		String username = tokenProvider.getUsernameFromToken(refreshToken);
		String userUUID = tokenProvider.getUserIDFromToken(refreshToken);

		UserDetails userDetails = userService.loadUserByUsername(username);

		Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
				userDetails.getAuthorities());

		SecurityContextHolder.getContext().setAuthentication(authentication);

		String newAccessToken = tokenProvider.generateAccessToken(authentication, userUUID);
		String newRefreshToken = tokenProvider.generateRefreshToken(username, userUUID);
		Date expiresAt = tokenProvider.extractExpiration(newAccessToken);

		ResponseCookie cookie = ResponseCookie.from("refreshToken", newRefreshToken).httpOnly(true).secure(true)
				.sameSite("Strict").path("/api/auth/refresh-token").maxAge(Duration.ofDays(7)).build();

		response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
		response.addHeader("Authorization", "Bearer " + newAccessToken);

		// Format expiresAt to ISO_OFFSET_DATE_TIME
		DateTimeFormatter formatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
		String formatted = expiresAt.toInstant().atZone(ZoneId.systemDefault()).format(formatter);

		JSONResponseDTO refreshTokenResponse = JSONResponseDTO.builder().isError(false)
				.data(Map.of("accessToken", newAccessToken, "expiresAt", formatted)).build();
		return ResponseEntity.ok(refreshTokenResponse);
	}

	public ResponseEntity<JSONResponseDTO<UserRolesResponseDTO>> getRoles(String username) {
		UserInfo user = userService.findUserByUsername(username)
				.orElseThrow(() -> new UserNotFoundException(RequestStatus.USER_NOT_FOUND));

		Set<GrantedAuthority> authorities = userService.getAuthorities(user.getUuid());

		List<String> roles = authorities.stream().filter(auth -> auth.getAuthority().startsWith("ROLE_"))
				.map(auth -> auth.getAuthority().substring("ROLE_".length())).distinct().collect(Collectors.toList());

		List<String> permissions = permissionsRepo.findAllByRoleIn(roles).stream().map(p->p.getPermission()).collect(Collectors.toList());

		UserRolesResponseDTO response = UserRolesResponseDTO.builder().userId(user.getUuid()).roles(roles)
				.permissions(permissions).build();

		return ResponseEntity.ok(
				AppUtils.getJSONObject(response, RequestStatus.ROLE_SUCCESS.getDescription(username)));
	}

}
