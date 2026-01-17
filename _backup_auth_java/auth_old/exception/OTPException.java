package com.src.main.auth.exception;

import com.src.main.common.exception.AbstractRuntimeException;

import com.src.main.common.util.RequestStatus;

public class OTPException extends AbstractRuntimeException {

	public OTPException(RequestStatus error,Object... msgParams) {
        super(error.getCode(),error.getDescription(msgParams));
    }
}
