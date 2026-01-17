package com.src.main.auth.transformer;

import org.springframework.stereotype.Component;

import com.src.main.auth.dto.SignupRequestDTO;
import com.src.main.auth.model.UserInfo;
import com.src.main.auth.service.UserDetailsServiceImpl;

import lombok.AllArgsConstructor;

@AllArgsConstructor
@Component
public class UserInfoTransformer {

	final UserDetailsServiceImpl userService;

	public UserInfo fromSignupRequestDTO(SignupRequestDTO signupRequest) {
		UserInfo userInfo = UserInfo.builder().username(signupRequest.getEmail()).email(signupRequest.getEmail())
				.password(signupRequest.getPassword()).build();
		return userInfo;
	}
}
