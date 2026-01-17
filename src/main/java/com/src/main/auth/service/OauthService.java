package com.src.main.auth.service;

import java.net.URL;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import com.src.main.auth.model.IdentifierType;
import com.src.main.auth.model.Role;
import com.src.main.auth.model.TenantRole;
import com.src.main.auth.model.User;
import com.src.main.auth.model.UserStatus;
import com.src.main.auth.repository.RoleRepository;
import com.src.main.auth.repository.TenantRoleRepository;
import com.src.main.auth.repository.UserRepository;
import com.src.main.auth.repository.UserRoleRepository;
import com.src.main.auth.repository.UserTenantRepository;
import com.src.main.auth.repository.UserTenantRoleRepository;
import com.src.main.auth.repository.UserTenantVerificationRepository;
import com.src.main.auth.tenant.TenantConfig;
import com.src.main.auth.tenant.TenantContextService;
import com.src.main.auth.util.CryptoUtils;

@Service
public class OauthService {
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final TenantRoleRepository tenantRoleRepository;
	private final UserRoleRepository userRoleRepository;
	private final UserTenantRepository userTenantRepository;
	private final UserTenantRoleRepository userTenantRoleRepository;
	private final UserTenantVerificationRepository userTenantVerificationRepository;
	private final TenantContextService tenantContext;
	private final String googleClientId;
	private final String appleClientId;

	public OauthService(
			UserRepository userRepository,
			RoleRepository roleRepository,
			TenantRoleRepository tenantRoleRepository,
			UserRoleRepository userRoleRepository,
			UserTenantRepository userTenantRepository,
			UserTenantRoleRepository userTenantRoleRepository,
			UserTenantVerificationRepository userTenantVerificationRepository,
			TenantContextService tenantContext,
			@Value("${oauth.google.client-id:}") String googleClientId,
			@Value("${oauth.apple.client-id:}") String appleClientId) {
		this.userRepository = userRepository;
		this.roleRepository = roleRepository;
		this.tenantRoleRepository = tenantRoleRepository;
		this.userRoleRepository = userRoleRepository;
		this.userTenantRepository = userTenantRepository;
		this.userTenantRoleRepository = userTenantRoleRepository;
		this.userTenantVerificationRepository = userTenantVerificationRepository;
		this.tenantContext = tenantContext;
		this.googleClientId = googleClientId;
		this.appleClientId = appleClientId;
	}

	public String verifyGoogleIdToken(String idToken) {
		try {
			if (googleClientId == null || googleClientId.isBlank()) {
				throw new IllegalArgumentException("GOOGLE_CLIENT_ID not configured");
			}
			GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
					GoogleNetHttpTransport.newTrustedTransport(), JacksonFactory.getDefaultInstance())
					.setAudience(List.of(googleClientId))
					.build();
			GoogleIdToken token = verifier.verify(idToken);
			if (token == null) {
				throw new IllegalArgumentException("Invalid Google token");
			}
			String email = token.getPayload().getEmail();
			if (email == null || email.isBlank()) {
				throw new IllegalArgumentException("Email not present in Google token");
			}
			return email;
		} catch (Exception ex) {
			throw new IllegalArgumentException("Invalid Google token", ex);
		}
	}

	public String verifyAppleIdentityToken(String identityToken) {
		try {
			if (appleClientId == null || appleClientId.isBlank()) {
				throw new IllegalArgumentException("APPLE_CLIENT_ID not configured");
			}
			ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
			JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL("https://appleid.apple.com/auth/keys"));
			JWSKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
			processor.setJWSKeySelector(selector);
			JWTClaimsSet claims = processor.process(identityToken, new SimpleSecurityContext());
			if (!"https://appleid.apple.com".equals(claims.getIssuer())) {
				throw new IllegalArgumentException("Invalid Apple identity token");
			}
			if (claims.getAudience() == null || !claims.getAudience().contains(appleClientId)) {
				throw new IllegalArgumentException("Invalid Apple identity token");
			}
			String email = claims.getStringClaim("email");
			if (email == null || email.isBlank()) {
				throw new IllegalArgumentException("Email not present in Apple token");
			}
			return email;
		} catch (Exception ex) {
			throw new IllegalArgumentException("Invalid Apple identity token", ex);
		}
	}

	public String upsertOauthUser(String email) {
		TenantConfig tenant = getTenant();
		String identifier = email.trim().toLowerCase();
		User existing = userRepository.findByIdentifier(identifier).orElse(null);
		if (existing != null) {
			if (existing.getStatus() != UserStatus.ACTIVE) {
				existing.setStatus(UserStatus.ACTIVE);
				userRepository.save(existing);
			}
			ensureMembership(existing.getId(), tenant.getId());
			return existing.getId();
		}

		User user = new User();
		user.setIdentifier(identifier);
		user.setIdentifierType(IdentifierType.EMAIL);
		user.setPasswordHash(CryptoUtils.hashPassword("oauth-" + CryptoUtils.uuid()));
		user.setStatus(UserStatus.ACTIVE);
		userRepository.save(user);

		ensureRole("ROLE_USER");
		UserRoleRepository userRoleRepo = userRoleRepository;
		com.src.main.auth.model.UserRole userRole = new com.src.main.auth.model.UserRole();
		userRole.setUserId(user.getId());
		userRole.setRoleName("ROLE_USER");
		userRoleRepo.save(userRole);

		TenantRole tenantRole = ensureTenantRole(tenant.getId(), "ROLE_USER");
		com.src.main.auth.model.UserTenant userTenant = new com.src.main.auth.model.UserTenant();
		userTenant.setUserId(user.getId());
		userTenant.setTenantId(tenant.getId());
		userTenant.setActive(true);
		userTenantRepository.save(userTenant);

		com.src.main.auth.model.UserTenantRole assign = new com.src.main.auth.model.UserTenantRole();
		assign.setUserId(user.getId());
		assign.setTenantRoleId(tenantRole.getId());
		userTenantRoleRepository.save(assign);

		com.src.main.auth.model.UserTenantVerification verification = new com.src.main.auth.model.UserTenantVerification();
		verification.setUserId(user.getId());
		verification.setTenantId(tenant.getId());
		verification.setEmailVerified(true);
		userTenantVerificationRepository.save(verification);

		return user.getId();
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

	private TenantConfig getTenant() {
		TenantConfig tenant = tenantContext.getTenant();
		if (tenant == null) {
			throw new IllegalArgumentException("Tenant context is not set");
		}
		return tenant;
	}

	private void ensureMembership(String userId, String tenantId) {
		userTenantRepository.findByUserIdAndTenantIdAndIsActiveTrue(userId, tenantId)
				.orElseGet(() -> {
					com.src.main.auth.model.UserTenant tenant = new com.src.main.auth.model.UserTenant();
					tenant.setUserId(userId);
					tenant.setTenantId(tenantId);
					tenant.setActive(true);
					return userTenantRepository.save(tenant);
				});
	}
}
