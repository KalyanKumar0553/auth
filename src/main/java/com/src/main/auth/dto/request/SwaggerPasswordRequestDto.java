package com.src.main.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class SwaggerPasswordRequestDto {
	@NotEmpty
	private String username;

	@NotEmpty
	@Size(min = 8, max = 72)
	@Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d).+$", message = "Password must include letters and numbers")
	private String password;

	@NotEmpty
	private String confirmPassword;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getConfirmPassword() {
		return confirmPassword;
	}

	public void setConfirmPassword(String confirmPassword) {
		this.confirmPassword = confirmPassword;
	}

	@AssertTrue(message = "Passwords do not match")
	public boolean isPasswordConfirmed() {
		return password != null && password.equals(confirmPassword);
	}
}
