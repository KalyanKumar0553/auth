package com.src.main.auth.security;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.src.main.auth.repository.InvalidatedTokenRepository;
import com.src.main.auth.util.JwtClaims;
import com.src.main.auth.util.JwtUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
	private final JwtUtils jwtUtils;
	private final InvalidatedTokenRepository invalidatedTokenRepository;

	public JwtAuthenticationFilter(JwtUtils jwtUtils, InvalidatedTokenRepository invalidatedTokenRepository) {
		this.jwtUtils = jwtUtils;
		this.invalidatedTokenRepository = invalidatedTokenRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String header = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (header != null && header.startsWith("Bearer ")) {
			String token = header.substring(7);
			if (invalidatedTokenRepository.existsByToken(token)) {
				SecurityContextHolder.clearContext();
				filterChain.doFilter(request, response);
				return;
			}
			try {
				JwtClaims claims = jwtUtils.parse(token);
				List<SimpleGrantedAuthority> authorities = claims.getRoles() == null
						? Collections.emptyList()
						: claims.getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
				UsernamePasswordAuthenticationToken auth =
						new UsernamePasswordAuthenticationToken(claims.getSub(), token, authorities);
				SecurityContextHolder.getContext().setAuthentication(auth);
			} catch (Exception ignored) {
				SecurityContextHolder.clearContext();
			}
		}
		filterChain.doFilter(request, response);
	}
}
