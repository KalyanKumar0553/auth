package com.src.main.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ResetPasswordWithoutOTPRequestDTO {
	@NotBlank(message = "Email is required")
	@Email(message = "Invalid email format")
	private String email;

	@NotBlank(message = "Password is required")
	@Size(min = 8, max = 30, message = "Password must be between 8 and 30 characters")
	@Pattern(regexp = ".*[A-Z].*", message = "Password must contain at least one uppercase letter")
	@Pattern(regexp = ".*[a-z].*", message = "Password must contain at least one lowercase letter")
	@Pattern(regexp = ".*[0-9].*", message = "Password must contain at least one digit")
	@Pattern(regexp = ".*[@#$%*()_].*", message = "Password must contain at least one special character: @ # $ % * ( ) _")
	@Pattern(regexp = "^[A-Za-z0-9@#$%*()_]+$", message = "Password contains invalid characters. Only letters, digits, and @ # $ % * ( ) _ are allowed")
	private String password;
	
	@NotBlank(message = "Retype password is required")
	private String retypePassword;
}
