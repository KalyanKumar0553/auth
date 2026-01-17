package com.src.main.auth.config;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.src.main.auth.model.InvalidatedToken;
import com.src.main.auth.repository.InvalidatedTokenRepository;
import com.src.main.auth.repository.RefreshTokenRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class JWTTokenProvider {

	private final String JWT_SECRET = "6rvQrbY7/yDbU6JfDdpHA9gN5Q/w7fhgJEBde0x6CTJtV8Pyyyhqaw+k5HKbfMlvg6nstoAZ2SjkZfte7Ehgqg==";

	private final long ACCESS_TOKEN_EXPIRATION = 15 * 60 * 1000L; // 15 minutes

	private final long REFRESH_TOKEN_EXPIRATION = 7 * 24 * 60 * 60 * 1000; // 7 days

	private final InvalidatedTokenRepository tokenRepository;

	private final RefreshTokenRepository refreshTokenRepository;

	private final Cache<String, Boolean> invalidatedTokenCache = Caffeine.newBuilder()
			.expireAfterWrite(25, TimeUnit.MINUTES).maximumSize(50000).build();

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	public Claims extractAllClaims(String token) {
		return Jwts.parser().setSigningKey(JWT_SECRET.getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token).getBody();
	}

	private boolean isTokenExpired(String token) {
		Date expiration = extractExpiration(token);
		LocalDateTime exp = Instant.ofEpochMilli(expiration.getTime()).atZone(ZoneId.systemDefault()).toLocalDateTime();
		return exp.isBefore(LocalDateTime.now());
	}

	@Transactional
	public void invalidateToken(String token) {
		Date expirationDate = extractExpiration(token);
		LocalDateTime expiration = Instant.ofEpochMilli(expirationDate.getTime()).atZone(ZoneId.systemDefault())
				.toLocalDateTime();
		InvalidatedToken invalidateToken = InvalidatedToken.builder().token(token).expirationDate(expiration).build();
		invalidatedTokenCache.put(token, true);
		tokenRepository.save(invalidateToken);
	}

	public boolean isTokenInvalidated(String token) {
		return invalidatedTokenCache.get(token, this::checkInvalidationInDB);
	}

	private boolean checkInvalidationInDB(String token) {
		return tokenRepository.existsByToken(token);
	}

	public String getUsernameFromToken(String token) {
		return extractAllClaims(token).getSubject();
	}

	public String getUserIDFromToken(String token) {
		return extractAllClaims(token).get("userUUID", String.class);
	}

	public boolean validateToken(String authToken) {
		try {
			Claims claims = extractAllClaims(authToken);
			if (claims.getExpiration().before(new Date())) {
				return false;
			}
			if (isTokenInvalidated(authToken)) {
				return false;
			}
			return true;
		} catch (JwtException | IllegalArgumentException | ExpiredJwtException ex) {
			return false;
		}
	}

	public List<String> getRolesFromJWT(String token) {
		Claims claims = extractAllClaims(token);
		return claims.get("roles", List.class);
	}

	public String generateAccessToken(Authentication authentication, String userUUID) {
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		List<String> roles = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
				.collect(Collectors.toList());

		Date expiryDate = new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION);

		return Jwts.builder().setSubject(userDetails.getUsername()).claim("userUUID", userUUID).claim("roles", roles)
				.setIssuedAt(new Date()).setExpiration(expiryDate)
				.signWith(SignatureAlgorithm.HS512, JWT_SECRET.getBytes(StandardCharsets.UTF_8)).compact();
	}

	public String generateRefreshToken(String username, String userUUID) {
		Date expiryDate = new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION);

		return Jwts.builder().setSubject(username).claim("userUUID", userUUID).setIssuedAt(new Date())
				.setExpiration(expiryDate)
				.signWith(SignatureAlgorithm.HS512, JWT_SECRET.getBytes(StandardCharsets.UTF_8)).compact();
	}

	public boolean isRefreshTokenValid(String token) {
		return refreshTokenRepository.findByToken(token).filter(t -> t.getExpiration().isAfter(LocalDateTime.now()))
				.isPresent();
	}
	
	public String getUsernameFromJWT(String token) {
		return extractAllClaims(token).getSubject();
	}

	@Transactional
	public void invalidateRefreshToken(String token) {
		refreshTokenRepository.deleteById(token);
	}
}
