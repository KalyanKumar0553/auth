package com.src.main.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.src.main.auth.repository.InvalidatedTokenRepository;
import com.src.main.auth.security.JwtAuthenticationFilter;
import com.src.main.auth.util.JwtUtils;

@Configuration
@EnableMethodSecurity
@org.springframework.core.annotation.Order(3)
public class SecurityConfig {
	@Value("${jwt.secret:change-me}")
	private String jwtSecret;

	@Value("${jwt.issuer:auth-service}")
	private String jwtIssuer;

	@Bean
	public JwtUtils jwtUtils() {
		return new JwtUtils(jwtIssuer, jwtSecret);
	}

	@Bean
	public SecurityFilterChain filterChain(
			HttpSecurity http,
			InvalidatedTokenRepository invalidatedTokenRepository,
			JwtUtils jwtUtils) throws Exception {
		http.csrf(csrf -> csrf.disable())
				.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/health", "/actuator/health").permitAll()
						.requestMatchers("/api/openapi/**").permitAll()
						.requestMatchers("/api/v1/auth/**").permitAll()
						.requestMatchers("/api/v1/admin/auth/**").permitAll()
						.requestMatchers("/api/v1/admin/swagger/token").authenticated()
						.anyRequest().authenticated());

		http.addFilterBefore(new JwtAuthenticationFilter(jwtUtils, invalidatedTokenRepository), UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}
}
