package com.src.main.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.src.main.auth.model.Setting;
import com.src.main.auth.repository.SettingRepository;

@Configuration
public class SwaggerSecurityConfig {

	@Bean
	@Order(2)
	public SecurityFilterChain swaggerFilterChain(HttpSecurity http) throws Exception {
		http.securityMatcher("/swagger-ui.html", "/swagger-ui/**");
		http.csrf(csrf -> csrf.ignoringRequestMatchers("/swagger-ui/**", "/swagger-ui.html"));
		http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());
		return http.build();
	}

	@Bean
	public PasswordEncoder swaggerPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public UserDetailsService swaggerUserDetailsService(SettingRepository settingRepository,
			PasswordEncoder passwordEncoder) {
		return username -> {
			try {
				Setting setting = settingRepository.findFirstBySourceAndUsername("swagger", username).orElse(null);
				if (setting == null || setting.getHash() == null) {
					if (!"swagger".equals(username)) {
						throw new UsernameNotFoundException("Swagger credentials not configured");
					}
					return User.withUsername("swagger")
							.password(passwordEncoder.encode("swagger1234"))
							.roles("SWAGGER")
							.build();
				}
				return User.withUsername(username)
						.password(setting.getHash())
						.passwordEncoder(pw -> pw)
						.roles("SWAGGER")
						.build();
			} catch (RuntimeException ex) {
				if (!"swagger".equals(username)) {
					throw ex;
				}
				return User.withUsername("swagger")
						.password(passwordEncoder.encode("swagger1234"))
						.roles("SWAGGER")
						.build();
			}
		};
	}
}
