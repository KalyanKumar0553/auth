package com.src.main.auth.service;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.src.main.auth.dto.response.TokenPairResponseDto;
import com.src.main.auth.model.IdentifierType;
import com.src.main.auth.model.OtpPurpose;
import com.src.main.auth.model.OtpRequest;
import com.src.main.auth.model.RefreshToken;
import com.src.main.auth.model.Role;
import com.src.main.auth.model.Setting;
import com.src.main.auth.model.User;
import com.src.main.auth.model.UserRole;
import com.src.main.auth.model.UserStatus;
import com.src.main.auth.repository.OtpRequestRepository;
import com.src.main.auth.repository.InvalidatedTokenRepository;
import com.src.main.auth.repository.RefreshTokenRepository;
import com.src.main.auth.repository.RoleRepository;
import com.src.main.auth.repository.SettingRepository;
import com.src.main.auth.repository.UserRepository;
import com.src.main.auth.repository.UserRoleRepository;
import com.src.main.auth.util.CryptoUtils;
import com.src.main.auth.util.IdentifierUtils;
import com.src.main.auth.util.JwtClaims;
import com.src.main.auth.util.JwtUtils;

@Service
public class AuthService {
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final UserRoleRepository userRoleRepository;
	private final OtpRequestRepository otpRequestRepository;
	private final RefreshTokenRepository refreshTokenRepository;
	private final InvalidatedTokenRepository invalidatedTokenRepository;
	private final SettingRepository settingRepository;
	private final JwtUtils jwtUtils;
	private final OtpSender otpSender;
	private final CaptchaService captchaService;

	private final long accessTtl;
	private final long refreshTtl;
	private final long otpTtl;
	private final long otpCooldown;
	private final int otpDailyLimit;
	private final int maxFailed;
	private final long lockoutSeconds;

	public AuthService(
			UserRepository userRepository,
			RoleRepository roleRepository,
			UserRoleRepository userRoleRepository,
			OtpRequestRepository otpRequestRepository,
			RefreshTokenRepository refreshTokenRepository,
			InvalidatedTokenRepository invalidatedTokenRepository,
			SettingRepository settingRepository,
			JwtUtils jwtUtils,
			OtpSender otpSender,
			CaptchaService captchaService,
			@Value("${jwt.access.ttl.seconds:900}") long accessTtl,
			@Value("${jwt.refresh.ttl.seconds:604800}") long refreshTtl,
			@Value("${otp.ttl.seconds:300}") long otpTtl,
			@Value("${otp.resend.cooldown.seconds:180}") long otpCooldown,
			@Value("${otp.daily.limit:5}") int otpDailyLimit,
			@Value("${security.max.failed.logins:5}") int maxFailed,
			@Value("${security.lockout.seconds:900}") long lockoutSeconds) {
		this.userRepository = userRepository;
		this.roleRepository = roleRepository;
		this.userRoleRepository = userRoleRepository;
		this.otpRequestRepository = otpRequestRepository;
		this.refreshTokenRepository = refreshTokenRepository;
		this.invalidatedTokenRepository = invalidatedTokenRepository;
		this.settingRepository = settingRepository;
		this.jwtUtils = jwtUtils;
		this.otpSender = otpSender;
		this.captchaService = captchaService;
		this.accessTtl = accessTtl;
		this.refreshTtl = refreshTtl;
		this.otpTtl = otpTtl;
		this.otpCooldown = otpCooldown;
		this.otpDailyLimit = otpDailyLimit;
		this.maxFailed = maxFailed;
		this.lockoutSeconds = lockoutSeconds;
	}

	public boolean identifierExists(String identifier) {
		String id = IdentifierUtils.normalizeIdentifier(identifier);
		return userRepository.findByIdentifier(id).isPresent();
	}

	@Transactional
	public void signup(String identifier, String password, String captchaId, String captchaText) {
		captchaService.verify(captchaId, captchaText);
		String normalized = IdentifierUtils.normalizeIdentifier(identifier);
		IdentifierType type = IdentifierUtils.classify(normalized);
		User existing = userRepository.findByIdentifier(normalized).orElse(null);

		ensureRole("ROLE_USER");
		if (existing != null) {
			throw new IllegalStateException("Identifier already exists");
		}
		User user = new User();
		user.setIdentifier(normalized);
		user.setIdentifierType(type);
		user.setPasswordHash(CryptoUtils.hashPassword(password));
		user.setStatus(UserStatus.PENDING_VERIFICATION);
		userRepository.save(user);

		UserRole userRole = new UserRole();
		userRole.setUserId(user.getId());
		userRole.setRoleName("ROLE_USER");
		userRoleRepository.save(userRole);

		generateOtpForUser(normalized, OtpPurpose.SIGNUP_VERIFICATION);
	}

	public CaptchaService.CaptchaResult generateCaptcha() {
		return captchaService.generate();
	}

	public void generateOtpForSignup(String identifier, String captchaId, String captchaText) {
		captchaService.verify(captchaId, captchaText);
		findUser(identifier);
		generateOtpForUser(identifier, OtpPurpose.SIGNUP_VERIFICATION);
	}

	@Transactional
	public void verifySignupOtp(String identifier, String otp) {
		User user = findUser(identifier);
		OtpRequest req = latestOtp(user.getId(), OtpPurpose.SIGNUP_VERIFICATION);
		if (req.getExpiresAt().isBefore(Instant.now())) {
			throw new IllegalArgumentException("OTP expired");
		}
		String expected = CryptoUtils.sha256Base64(otp, null);
		if (!expected.equals(req.getOtpHash())) {
			throw new IllegalArgumentException("Invalid OTP");
		}

		req.setUsed(true);
		otpRequestRepository.save(req);
		user.setStatus(UserStatus.ACTIVE);
		userRepository.save(user);
		revokeUserRefreshTokens(user.getId());
	}

	public void forgotPassword(String identifier, String captchaId, String captchaText) {
		captchaService.verify(captchaId, captchaText);
		findUser(identifier);
		generateOtpForUser(identifier, OtpPurpose.PASSWORD_RESET);
	}

	@Transactional
	public void resetPassword(String identifier, String otp, String newPassword) {
		User user = findUser(identifier);
		if (user.getStatus() != UserStatus.ACTIVE) {
			throw new IllegalArgumentException("User is not active");
		}

		OtpRequest req = latestOtp(user.getId(), OtpPurpose.PASSWORD_RESET);
		if (req.getExpiresAt().isBefore(Instant.now())) {
			throw new IllegalArgumentException("OTP expired");
		}
		String expected = CryptoUtils.sha256Base64(otp, null);
		if (!expected.equals(req.getOtpHash())) {
			throw new IllegalArgumentException("Invalid OTP");
		}

		req.setUsed(true);
		otpRequestRepository.save(req);
		user.setPasswordHash(CryptoUtils.hashPassword(newPassword));
		userRepository.save(user);
		revokeUserRefreshTokens(user.getId());
	}

	@Transactional
	public TokenPairResponseDto login(String identifier, String password) {
		User user = userRepository.findByIdentifier(IdentifierUtils.normalizeIdentifier(identifier))
				.orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));
		Instant now = Instant.now();
		if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(now)) {
			throw new IllegalArgumentException("Account temporarily locked. Try later.");
		}
		if (user.getStatus() != UserStatus.ACTIVE) {
			throw new IllegalArgumentException("User is not active");
		}

		boolean ok = CryptoUtils.verifyPassword(password, user.getPasswordHash());
		if (!ok) {
			int attempts = user.getFailedLoginAttempts() + 1;
			if (attempts >= maxFailed) {
				user.setLockedUntil(now.plusSeconds(lockoutSeconds));
				user.setFailedLoginAttempts(0);
			} else {
				user.setFailedLoginAttempts(attempts);
			}
			userRepository.save(user);
			throw new IllegalArgumentException("Invalid credentials");
		}

		user.setFailedLoginAttempts(0);
		user.setLockedUntil(null);
		userRepository.save(user);
		return issueTokens(user.getId());
	}

	public TokenPairResponseDto loginWithUserId(String userId) {
		User user = userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("User not found"));
		if (user.getStatus() != UserStatus.ACTIVE) {
			throw new IllegalArgumentException("User is not active");
		}
		return issueTokens(user.getId());
	}

	@Transactional
	public TokenPairResponseDto refresh(String refreshTokenJwt) {
		JwtClaims claims = jwtUtils.parse(refreshTokenJwt);
		if (!"refresh".equals(claims.getTyp()) || claims.getRid() == null) {
			throw new IllegalArgumentException("Not a refresh token");
		}

		RefreshToken token = refreshTokenRepository
				.findFirstByIdAndRevokedFalseAndExpiresAtAfter(claims.getRid(), Instant.now())
				.orElse(null);
		if (token == null) {
			RefreshToken any = refreshTokenRepository.findById(claims.getRid()).orElse(null);
			if (any != null) {
				revokeFamily(any.getFamilyId());
			}
			throw new IllegalArgumentException("Refresh token revoked or expired");
		}

		token.setRevoked(true);
		refreshTokenRepository.save(token);

		User user = userRepository.findById(claims.getSub()).orElseThrow(() -> new IllegalArgumentException("User not found"));
		if (user.getStatus() != UserStatus.ACTIVE) {
			throw new IllegalArgumentException("User is not active");
		}
		return issueTokens(user.getId(), token.getFamilyId());
	}

	@Transactional
	public void logout(String refreshTokenJwt, String accessToken) {
		JwtClaims claims = jwtUtils.parse(refreshTokenJwt);
		if (!"refresh".equals(claims.getTyp()) || claims.getRid() == null) {
			throw new IllegalArgumentException("Not a refresh token");
		}
		RefreshToken token = refreshTokenRepository.findById(claims.getRid()).orElse(null);
		if (token != null) {
			token.setRevoked(true);
			refreshTokenRepository.save(token);
		}
		invalidateAccessToken(accessToken);
	}

	public void invalidateAccessToken(String accessToken) {
		if (accessToken == null || accessToken.isBlank()) {
			return;
		}
		String token = accessToken.startsWith("Bearer ") ? accessToken.substring(7) : accessToken;
		try {
			JwtClaims claims = jwtUtils.parse(token);
			if (!"access".equals(claims.getTyp())) {
				return;
			}
			if (invalidatedTokenRepository.existsByToken(token)) {
				return;
			}
			com.src.main.auth.model.InvalidatedToken invalidated = new com.src.main.auth.model.InvalidatedToken();
			invalidated.setToken(token);
			invalidated.setExpiresAt(jwtUtils.getExpiration(token));
			invalidatedTokenRepository.save(invalidated);
		} catch (Exception ignored) {
			// Ignore invalid/expired tokens during logout
		}
	}

	public boolean validate(String token) {
		try {
			jwtUtils.parse(token);
			return true;
		} catch (Exception ex) {
			return false;
		}
	}

	@Transactional
	public void updateSwaggerPassword(String username, String password) {
		String hash = CryptoUtils.hashPassword(password);
		Setting setting = settingRepository.findFirstBySourceAndUsername("swagger", username).orElse(null);
		if (setting == null) {
			setting = new Setting();
			setting.setSource("swagger");
			setting.setUsername(username);
		}
		setting.setHash(hash);
		setting.setPassword(null);
		setting.setSalt(null);
		settingRepository.save(setting);
	}

	public String issueSwaggerToken(String username, String password) {
		Setting setting = settingRepository.findFirstBySourceAndUsername("swagger", username).orElse(null);
		if (setting == null || setting.getHash() == null) {
			if (!"swagger".equals(username) || !"swagger1234".equals(password)) {
				throw new IllegalArgumentException("Invalid swagger credentials");
			}
			return jwtUtils.signAccess("swagger:" + username, List.of("ROLE_SWAGGER_ADMIN"), accessTtl);
		}
		if (!CryptoUtils.verifyPassword(password, setting.getHash())) {
			throw new IllegalArgumentException("Invalid swagger credentials");
		}
		return jwtUtils.signAccess("swagger:" + username, List.of("ROLE_SWAGGER_ADMIN"), accessTtl);
	}

	public List<String> getUserRoles(String userId) {
		return getUserRolesByUserId(userId);
	}

	private void generateOtpForUser(String identifier, OtpPurpose purpose) {
		User user = findUser(identifier);
		Instant start = LocalDate.now(ZoneOffset.UTC).atStartOfDay().toInstant(ZoneOffset.UTC);
		Instant end = start.plusSeconds(24 * 60 * 60 - 1);
		long sentToday = otpRequestRepository.countByUserIdAndCreatedAtBetween(user.getId(), start, end);
		if (sentToday >= otpDailyLimit) {
			throw new IllegalArgumentException("Daily OTP limit exceeded (" + otpDailyLimit + ")");
		}

		OtpRequest latest = otpRequestRepository
				.findFirstByUserIdAndPurposeAndUsedFalseOrderByCreatedAtDesc(user.getId(), purpose)
				.orElse(null);
		if (latest != null) {
			long secondsSince = Instant.now().getEpochSecond() - latest.getCreatedAt().getEpochSecond();
			if (secondsSince < otpCooldown) {
				throw new IllegalArgumentException("Please wait " + otpCooldown + " seconds between OTP requests");
			}
		}

		String otp = CryptoUtils.generateOtp6();
		OtpRequest request = new OtpRequest();
		request.setUserId(user.getId());
		request.setPurpose(purpose);
		request.setOtpHash(CryptoUtils.sha256Base64(otp, null));
		request.setExpiresAt(Instant.now().plusSeconds(otpTtl));
		request.setUsed(false);
		otpRequestRepository.save(request);

		otpSender.send(user.getIdentifierType(), user.getIdentifier(), otp);
	}

	private OtpRequest latestOtp(String userId, OtpPurpose purpose) {
		return otpRequestRepository
				.findFirstByUserIdAndPurposeAndUsedFalseOrderByCreatedAtDesc(userId, purpose)
				.orElseThrow(() -> new IllegalArgumentException("No valid OTP found. Please request a new OTP."));
	}

	private TokenPairResponseDto issueTokens(String userId) {
		return issueTokens(userId, CryptoUtils.uuid());
	}

	private TokenPairResponseDto issueTokens(String userId, String familyId) {
		List<String> roles = getUserRolesByUserId(userId);
		String access = jwtUtils.signAccess(userId, roles, accessTtl);
		String refreshId = CryptoUtils.uuid();
		String refresh = jwtUtils.signRefresh(userId, refreshId, refreshTtl);

		RefreshToken token = new RefreshToken();
		token.setId(refreshId);
		token.setUserId(userId);
		token.setFamilyId(familyId);
		token.setTokenHash(CryptoUtils.sha256Base64(refresh, null));
		token.setExpiresAt(Instant.now().plusSeconds(refreshTtl));
		token.setRevoked(false);
		refreshTokenRepository.save(token);

		return new TokenPairResponseDto(access, refresh);
	}

	private void revokeUserRefreshTokens(String userId) {
		List<RefreshToken> tokens = refreshTokenRepository.findByUserId(userId);
		for (RefreshToken token : tokens) {
			token.setRevoked(true);
		}
		refreshTokenRepository.saveAll(tokens);
	}

	private void revokeFamily(String familyId) {
		List<RefreshToken> tokens = refreshTokenRepository.findByFamilyId(familyId);
		for (RefreshToken token : tokens) {
			token.setRevoked(true);
		}
		refreshTokenRepository.saveAll(tokens);
	}

	private void ensureRole(String name) {
		if (!roleRepository.existsById(name)) {
			Role role = new Role();
			role.setName(name);
			roleRepository.save(role);
		}
	}

	private User findUser(String identifier) {
		String id = IdentifierUtils.normalizeIdentifier(identifier);
		return userRepository.findByIdentifier(id).orElseThrow(() -> new IllegalArgumentException("User not found"));
	}

	private List<String> getUserRolesByUserId(String userId) {
		List<UserRole> assignments = userRoleRepository.findByUserId(userId);
		if (!assignments.isEmpty()) {
			return assignments.stream().map(UserRole::getRoleName).collect(Collectors.toList());
		}
		ensureRole("ROLE_USER");
		UserRole role = new UserRole();
		role.setUserId(userId);
		role.setRoleName("ROLE_USER");
		userRoleRepository.save(role);
		return List.of("ROLE_USER");
	}
}
