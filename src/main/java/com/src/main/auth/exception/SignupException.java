package com.src.main.auth.exception;

import com.src.main.common.exception.AbstractRuntimeException;

import com.src.main.common.util.RequestStatus;

public class SignupException extends AbstractRuntimeException {

	public SignupException(RequestStatus error,Object... msgParams) {
        super(error.getCode(),error.getDescription(msgParams));
    }
}
