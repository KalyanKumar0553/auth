package com.src.main.auth.util;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class JwtUtils {
	private final String issuer;
	private final byte[] secret;

	public JwtUtils(String issuer, String secret) {
		this.issuer = issuer;
		this.secret = secret.getBytes(StandardCharsets.UTF_8);
	}

	public String signAccess(String userId, List<String> roles, long ttlSeconds) {
		return signToken(new JwtClaims(userId, "access", null, roles), ttlSeconds);
	}

	public String signRefresh(String userId, String refreshId, long ttlSeconds) {
		return signToken(new JwtClaims(userId, "refresh", refreshId, null), ttlSeconds);
	}

	public JwtClaims parse(String token) {
		Claims claims = parseClaims(token);
		String sub = claims.getSubject();
		String typ = (String) claims.get("typ");
		String rid = (String) claims.get("rid");
		List<String> roles = claims.get("roles", List.class);
		JwtClaims parsed = new JwtClaims(sub, typ, rid, roles);
		parsed.setExpiration(claims.getExpiration());
		return parsed;
	}

	public Claims parseClaims(String token) {
		return Jwts.parserBuilder()
				.setSigningKey(Keys.hmacShaKeyFor(secret))
				.requireIssuer(issuer)
				.build()
				.parseClaimsJws(token)
				.getBody();
	}

	public Instant getExpiration(String token) {
		return parseClaims(token).getExpiration().toInstant();
	}

	private String signToken(JwtClaims claims, long ttlSeconds) {
		Instant now = Instant.now();
		return Jwts.builder()
				.setIssuer(issuer)
				.setSubject(claims.getSub())
				.setIssuedAt(Date.from(now))
				.setExpiration(Date.from(now.plusSeconds(ttlSeconds)))
				.claim("typ", claims.getTyp())
				.claim("rid", claims.getRid())
				.claim("roles", claims.getRoles())
				.signWith(Keys.hmacShaKeyFor(secret), SignatureAlgorithm.HS256)
				.compact();
	}
}
