package com.src.main.auth.validation;

import com.src.main.auth.dto.ResetPasswordRequestDTO;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordsMatchValidator implements ConstraintValidator<PasswordsMatch, ResetPasswordRequestDTO> {

    @Override
    public boolean isValid(ResetPasswordRequestDTO dto, ConstraintValidatorContext context) {
        if (dto.getPassword() == null || dto.getRetypePassword() == null) {
            return false;
        }
        return dto.getPassword().equals(dto.getRetypePassword());
    }
}
