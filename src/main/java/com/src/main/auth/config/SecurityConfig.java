package com.src.main.auth.config;

import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.src.main.auth.filter.JwtAuthenticationFilter;
import com.src.main.auth.service.UserDetailsServiceImpl;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
	private static final String LOGOUT_URL = "/logout";
	private static final String LOGOUT_SUCCESS_URL = "/logout";

	private final UserDetailsServiceImpl userDetailsService;
	private final JWTTokenProvider jwtTokenProvider;

	public SecurityConfig(UserDetailsServiceImpl userDetailsService, JWTTokenProvider jwtTokenProvider) {
		this.userDetailsService = userDetailsService;
		this.jwtTokenProvider = jwtTokenProvider;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		http.cors(Customizer.withDefaults()).csrf(AbstractHttpConfigurer::disable)

				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/assets/**", "/*.css", "/*.js", "/canvaskit/**", "/icons/*.png",
								"/icons/*.jpg", "/index.html", "/*.json", "/*.png", "/*.jpg", "/", "/*.woff2",
								LOGOUT_URL, "/actuator/health")
						.permitAll()
						.requestMatchers("/api/auth/**").permitAll()
						.requestMatchers("/api/config/**").permitAll()
						.requestMatchers("/api/user/**").hasRole("USER")
						.requestMatchers("/api/admin/**").hasRole("ADMIN")
						.anyRequest().authenticated())

				.logout(logout -> logout.logoutUrl(LOGOUT_URL).logoutSuccessUrl(LOGOUT_SUCCESS_URL)
						.deleteCookies("JSESSIONID").invalidateHttpSession(true).clearAuthentication(true))

				.exceptionHandling(ex -> ex.authenticationEntryPoint(
						(req, res, ex2) -> res.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex2.getMessage())))

				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		http.addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider, userDetailsService),
				UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowedOrigins(List.of("http://localhost:4200"));
		config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
		config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
		config.setExposedHeaders(List.of("Authorization"));
		config.setAllowCredentials(true);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		return source;
	}
}
