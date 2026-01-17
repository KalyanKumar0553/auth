package com.src.main.auth.dto.request;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class MatchPasswordValidator implements ConstraintValidator<SwaggerPasswordRequestDto.MatchPassword, String> {
	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {
		if (value == null) {
			return false;
		}
		Object root = context.getRootBean();
		if (root instanceof SwaggerPasswordRequestDto dto) {
			return value.equals(dto.getPassword());
		}
		return false;
	}
}
