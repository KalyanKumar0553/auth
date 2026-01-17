package com.src.main.auth.dto.common;

public class ApiResponseDto<T> {
	private boolean success;
	private String message;
	private T data;

	public ApiResponseDto() {}

	public ApiResponseDto(boolean success, String message, T data) {
		this.success = success;
		this.message = message;
		this.data = data;
	}

	public static <T> ApiResponseDto<T> ok(String message, T data) {
		return new ApiResponseDto<>(true, message, data);
	}

	public static <T> ApiResponseDto<T> ok(String message) {
		return new ApiResponseDto<>(true, message, null);
	}

	public static ApiResponseDto<Void> fail(String message) {
		return new ApiResponseDto<>(false, message, null);
	}

	public boolean isSuccess() {
		return success;
	}

	public void setSuccess(boolean success) {
		this.success = success;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public T getData() {
		return data;
	}

	public void setData(T data) {
		this.data = data;
	}
}
