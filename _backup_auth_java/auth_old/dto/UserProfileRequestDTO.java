package com.src.main.auth.dto;

import java.time.LocalDate;

import com.src.main.common.util.AppConstants;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UserProfileRequestDTO {
	@Size(max = 50, message = "Email must not exceed 50 characters")
    @Pattern(regexp = AppConstants.emailRegex, message = "Invalid email format")
    private String email;

    @Size(max = 50, message = "Full name must not exceed 50 characters")
    private String fullName;

    private LocalDate dob;

    private String profilePic;
}
