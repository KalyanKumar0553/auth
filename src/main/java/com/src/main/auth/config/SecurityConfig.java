package com.src.main.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.src.main.auth.repository.TenantRepository;
import com.src.main.auth.repository.TenantShaKeyRepository;
import com.src.main.auth.security.JwtAuthenticationFilter;
import com.src.main.auth.security.TenantContextFilter;
import com.src.main.auth.tenant.TenantContextService;
import com.src.main.auth.util.JwtUtils;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
	@Value("${jwt.secret:change-me}")
	private String jwtSecret;

	@Value("${jwt.issuer:auth-service}")
	private String jwtIssuer;

	@Value("${tenant.header.name:x-tenant-code}")
	private String tenantHeader;

	@Bean
	public JwtUtils jwtUtils() {
		return new JwtUtils(jwtIssuer, jwtSecret);
	}

	@Bean
	public SecurityFilterChain filterChain(
			HttpSecurity http,
			TenantRepository tenantRepository,
			TenantShaKeyRepository tenantShaKeyRepository,
			TenantContextService tenantContextService,
			JwtUtils jwtUtils) throws Exception {
		http.csrf(csrf -> csrf.disable())
				.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/health").permitAll()
						.requestMatchers("/api/v1/auth/**").permitAll()
						.anyRequest().authenticated());

		http.addFilterBefore(
				new TenantContextFilter(tenantRepository, tenantShaKeyRepository, tenantContextService, tenantHeader),
				UsernamePasswordAuthenticationFilter.class);
		http.addFilterBefore(new JwtAuthenticationFilter(jwtUtils), UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}
}
