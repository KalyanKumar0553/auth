package com.src.main.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class StaticContentSecurityConfig {

	@Bean
	@Order(1)
	public SecurityFilterChain staticContentFilterChain(HttpSecurity http) throws Exception {
		http.securityMatcher(
				"/",
				"/index.html",
				"/swagger-login.html",
				"/swagger-ui.html",
				"/swagger-ui-custom.html",
				"/favicon.ico",
				"/assets/**",
				"/*.png",
				"/*.svg",
				"/*.css",
				"/*.js",
				"/*.map"
		);
		http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());
		http.csrf(csrf -> csrf.disable());
		return http.build();
	}
}
