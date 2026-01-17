package com.src.main.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OTPSentResponseDTO {
    private boolean otpSent;
	private long expiresIn;
}