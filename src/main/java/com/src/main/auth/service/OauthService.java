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
import com.src.main.auth.model.User;
import com.src.main.auth.model.UserStatus;
import com.src.main.auth.repository.RoleRepository;
import com.src.main.auth.repository.UserRepository;
import com.src.main.auth.repository.UserRoleRepository;
import com.src.main.auth.util.CryptoUtils;

@Service
public class OauthService {
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final UserRoleRepository userRoleRepository;
	private final String googleClientId;
	private final String appleClientId;

	public OauthService(
			UserRepository userRepository,
			RoleRepository roleRepository,
			UserRoleRepository userRoleRepository,
			@Value("${oauth.google.client-id:}") String googleClientId,
			@Value("${oauth.apple.client-id:}") String appleClientId) {
		this.userRepository = userRepository;
		this.roleRepository = roleRepository;
		this.userRoleRepository = userRoleRepository;
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
		String identifier = email.trim().toLowerCase();
		User existing = userRepository.findByIdentifier(identifier).orElse(null);
		if (existing != null) {
			if (existing.getStatus() != UserStatus.ACTIVE) {
				existing.setStatus(UserStatus.ACTIVE);
				userRepository.save(existing);
			}
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

		return user.getId();
	}

	private void ensureRole(String name) {
		if (!roleRepository.existsById(name)) {
			Role role = new Role();
			role.setName(name);
			roleRepository.save(role);
		}
	}
}
