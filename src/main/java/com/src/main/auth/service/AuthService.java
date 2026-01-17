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
import com.src.main.auth.model.TenantRole;
import com.src.main.auth.model.User;
import com.src.main.auth.model.UserRole;
import com.src.main.auth.model.UserStatus;
import com.src.main.auth.model.UserTenant;
import com.src.main.auth.model.UserTenantRole;
import com.src.main.auth.model.UserTenantVerification;
import com.src.main.auth.repository.OtpRequestRepository;
import com.src.main.auth.repository.RefreshTokenRepository;
import com.src.main.auth.repository.RoleRepository;
import com.src.main.auth.repository.SettingRepository;
import com.src.main.auth.repository.TenantRoleRepository;
import com.src.main.auth.repository.UserRepository;
import com.src.main.auth.repository.UserRoleRepository;
import com.src.main.auth.repository.UserTenantRepository;
import com.src.main.auth.repository.UserTenantRoleRepository;
import com.src.main.auth.repository.UserTenantVerificationRepository;
import com.src.main.auth.tenant.TenantConfig;
import com.src.main.auth.tenant.TenantContextService;
import com.src.main.auth.util.CryptoUtils;
import com.src.main.auth.util.IdentifierUtils;
import com.src.main.auth.util.JwtClaims;
import com.src.main.auth.util.JwtUtils;

@Service
public class AuthService {
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final UserRoleRepository userRoleRepository;
	private final UserTenantRepository userTenantRepository;
	private final UserTenantRoleRepository userTenantRoleRepository;
	private final UserTenantVerificationRepository userTenantVerificationRepository;
	private final OtpRequestRepository otpRequestRepository;
	private final RefreshTokenRepository refreshTokenRepository;
	private final SettingRepository settingRepository;
	private final TenantRoleRepository tenantRoleRepository;
	private final TenantContextService tenantContext;
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
			UserTenantRepository userTenantRepository,
			UserTenantRoleRepository userTenantRoleRepository,
			UserTenantVerificationRepository userTenantVerificationRepository,
			OtpRequestRepository otpRequestRepository,
			RefreshTokenRepository refreshTokenRepository,
			SettingRepository settingRepository,
			TenantRoleRepository tenantRoleRepository,
			TenantContextService tenantContext,
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
		this.userTenantRepository = userTenantRepository;
		this.userTenantRoleRepository = userTenantRoleRepository;
		this.userTenantVerificationRepository = userTenantVerificationRepository;
		this.otpRequestRepository = otpRequestRepository;
		this.refreshTokenRepository = refreshTokenRepository;
		this.settingRepository = settingRepository;
		this.tenantRoleRepository = tenantRoleRepository;
		this.tenantContext = tenantContext;
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
		TenantConfig tenant = getTenant();
		String id = IdentifierUtils.normalizeIdentifier(identifier);
		User user = userRepository.findByIdentifier(id).orElse(null);
		if (user == null) return false;
		return userTenantRepository.findByUserIdAndTenantIdAndIsActiveTrue(user.getId(), tenant.getId()).isPresent();
	}

	@Transactional
	public void signup(String identifier, String password, String captchaId, String captchaText) {
		captchaService.verify(captchaId, captchaText);
		TenantConfig tenant = getTenant();
		String normalized = IdentifierUtils.normalizeIdentifier(identifier);
		IdentifierType type = IdentifierUtils.classify(normalized);
		User existing = userRepository.findByIdentifier(normalized).orElse(null);

		ensureRole("ROLE_USER");
		TenantRole tenantRole = ensureTenantRole(tenant.getId(), "ROLE_USER");

		if (existing != null) {
			UserTenant membership = userTenantRepository
					.findByUserIdAndTenantIdAndIsActiveTrue(existing.getId(), tenant.getId())
					.orElse(null);
			if (membership != null) {
				throw new IllegalStateException("Identifier already exists");
			}
			UserTenant newMembership = new UserTenant();
			newMembership.setUserId(existing.getId());
			newMembership.setTenantId(tenant.getId());
			newMembership.setActive(true);
			userTenantRepository.save(newMembership);

			UserTenantRole roleAssign = new UserTenantRole();
			roleAssign.setUserId(existing.getId());
			roleAssign.setTenantRoleId(tenantRole.getId());
			userTenantRoleRepository.save(roleAssign);

			UserTenantVerification verification = new UserTenantVerification();
			verification.setUserId(existing.getId());
			verification.setTenantId(tenant.getId());
			userTenantVerificationRepository.save(verification);
		} else {
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

			UserTenant userTenant = new UserTenant();
			userTenant.setUserId(user.getId());
			userTenant.setTenantId(tenant.getId());
			userTenant.setActive(true);
			userTenantRepository.save(userTenant);

			UserTenantRole roleAssign = new UserTenantRole();
			roleAssign.setUserId(user.getId());
			roleAssign.setTenantRoleId(tenantRole.getId());
			userTenantRoleRepository.save(roleAssign);

			UserTenantVerification verification = new UserTenantVerification();
			verification.setUserId(user.getId());
			verification.setTenantId(tenant.getId());
			userTenantVerificationRepository.save(verification);
		}

		generateOtpForUser(normalized, OtpPurpose.SIGNUP_VERIFICATION);
	}

	public CaptchaService.CaptchaResult generateCaptcha() {
		return captchaService.generate();
	}

	public void generateOtpForSignup(String identifier, String captchaId, String captchaText) {
		captchaService.verify(captchaId, captchaText);
		findUserForTenant(identifier);
		generateOtpForUser(identifier, OtpPurpose.SIGNUP_VERIFICATION);
	}

	@Transactional
	public void verifySignupOtp(String identifier, String otp) {
		TenantConfig tenant = getTenant();
		User user = findUserForTenant(identifier);
		OtpRequest req = latestOtp(user.getId(), OtpPurpose.SIGNUP_VERIFICATION);
		if (req.getExpiresAt().isBefore(Instant.now())) {
			throw new IllegalArgumentException("OTP expired");
		}
		String expected = CryptoUtils.sha256Base64(otp, tenant.getShaKey());
		if (!expected.equals(req.getOtpHash())) {
			throw new IllegalArgumentException("Invalid OTP");
		}

		req.setUsed(true);
		otpRequestRepository.save(req);
		user.setStatus(UserStatus.ACTIVE);
		userRepository.save(user);
		revokeUserRefreshTokens(user.getId());

		UserTenantVerification verification = userTenantVerificationRepository
				.findByUserIdAndTenantId(user.getId(), tenant.getId())
				.orElseGet(() -> {
					UserTenantVerification v = new UserTenantVerification();
					v.setUserId(user.getId());
					v.setTenantId(tenant.getId());
					return v;
				});
		if (user.getIdentifierType() == IdentifierType.EMAIL) {
			verification.setEmailVerified(true);
		} else {
			verification.setMobileVerified(true);
		}
		userTenantVerificationRepository.save(verification);
	}

	public void forgotPassword(String identifier, String captchaId, String captchaText) {
		captchaService.verify(captchaId, captchaText);
		findUserForTenant(identifier);
		generateOtpForUser(identifier, OtpPurpose.PASSWORD_RESET);
	}

	@Transactional
	public void resetPassword(String identifier, String otp, String newPassword) {
		TenantConfig tenant = getTenant();
		User user = findUserForTenant(identifier);
		if (user.getStatus() != UserStatus.ACTIVE) {
			throw new IllegalArgumentException("User is not active");
		}

		OtpRequest req = latestOtp(user.getId(), OtpPurpose.PASSWORD_RESET);
		if (req.getExpiresAt().isBefore(Instant.now())) {
			throw new IllegalArgumentException("OTP expired");
		}
		String expected = CryptoUtils.sha256Base64(otp, tenant.getShaKey());
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
		assertMembership(user.getId());
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
		assertMembership(user.getId());
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
		assertMembership(user.getId());
		return issueTokens(user.getId(), token.getFamilyId());
	}

	@Transactional
	public void logout(String refreshTokenJwt) {
		JwtClaims claims = jwtUtils.parse(refreshTokenJwt);
		if (!"refresh".equals(claims.getTyp()) || claims.getRid() == null) {
			throw new IllegalArgumentException("Not a refresh token");
		}
		assertMembership(claims.getSub());
		RefreshToken token = refreshTokenRepository.findById(claims.getRid()).orElse(null);
		if (token != null) {
			token.setRevoked(true);
			refreshTokenRepository.save(token);
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
			throw new IllegalArgumentException("Invalid swagger credentials");
		}
		if (!CryptoUtils.verifyPassword(password, setting.getHash())) {
			throw new IllegalArgumentException("Invalid swagger credentials");
		}
		return jwtUtils.signAccess("swagger:" + username, List.of("ROLE_SWAGGER_ADMIN"), null, accessTtl);
	}

	public List<String> getUserRoles(String userId) {
		assertMembership(userId);
		return getTenantRoles(userId);
	}

	private void generateOtpForUser(String identifier, OtpPurpose purpose) {
		TenantConfig tenant = getTenant();
		User user = findUserForTenant(identifier);
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
		request.setOtpHash(CryptoUtils.sha256Base64(otp, tenant.getShaKey()));
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
		List<String> roles = getTenantRoles(userId);
		String tenantCode = getTenant().getTenantCode();
		String access = jwtUtils.signAccess(userId, roles, tenantCode, accessTtl);
		String refreshId = CryptoUtils.uuid();
		String refresh = jwtUtils.signRefresh(userId, refreshId, tenantCode, refreshTtl);

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

	private TenantRole ensureTenantRole(String tenantId, String name) {
		return tenantRoleRepository.findByTenantIdAndName(tenantId, name)
				.orElseGet(() -> {
					TenantRole role = new TenantRole();
					role.setTenantId(tenantId);
					role.setName(name);
					role.setActive(true);
					return tenantRoleRepository.save(role);
				});
	}

	private void assertMembership(String userId) {
		TenantConfig tenant = getTenant();
		boolean ok = userTenantRepository
				.findByUserIdAndTenantIdAndIsActiveTrueAndTenantIsActiveTrue(userId, tenant.getId())
				.isPresent();
		if (!ok) {
			throw new IllegalArgumentException("Access to tenant denied");
		}
	}

	private User findUserForTenant(String identifier) {
		TenantConfig tenant = getTenant();
		String id = IdentifierUtils.normalizeIdentifier(identifier);
		User user = userRepository.findByIdentifier(id).orElseThrow(() -> new IllegalArgumentException("User not found"));
		boolean ok = userTenantRepository
				.findByUserIdAndTenantIdAndIsActiveTrue(user.getId(), tenant.getId())
				.isPresent();
		if (!ok) {
			throw new IllegalArgumentException("Access to tenant denied");
		}
		return user;
	}

	private List<String> getTenantRoles(String userId) {
		TenantConfig tenant = getTenant();
		List<UserTenantRole> assignments = userTenantRoleRepository
				.findByUserIdAndTenantRoleTenantIdAndTenantRoleIsActiveTrue(userId, tenant.getId());
		if (!assignments.isEmpty()) {
			return assignments.stream().map(a -> a.getTenantRole().getName()).collect(Collectors.toList());
		}

		TenantRole role = ensureTenantRole(tenant.getId(), "ROLE_USER");
		UserTenantRole assignment = new UserTenantRole();
		assignment.setUserId(userId);
		assignment.setTenantRoleId(role.getId());
		userTenantRoleRepository.save(assignment);
		return List.of("ROLE_USER");
	}

	private TenantConfig getTenant() {
		TenantConfig tenant = tenantContext.getTenant();
		if (tenant == null) {
			throw new IllegalArgumentException("Tenant context is not set");
		}
		return tenant;
	}
}
