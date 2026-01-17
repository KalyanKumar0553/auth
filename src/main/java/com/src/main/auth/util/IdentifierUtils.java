package com.src.main.auth.util;

import com.src.main.auth.model.IdentifierType;

public class IdentifierUtils {
	private static final java.util.regex.Pattern EMAIL = java.util.regex.Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");
	private static final java.util.regex.Pattern PHONE = java.util.regex.Pattern.compile("^\\+?\\d{10,15}$");

	private IdentifierUtils() {}

	public static String normalizeIdentifier(String value) {
		if (value == null || value.trim().isEmpty()) {
			throw new IllegalArgumentException("Identifier must not be blank");
		}
		return value.trim().toLowerCase();
	}

	public static boolean isEmail(String value) {
		return value != null && EMAIL.matcher(value).matches();
	}

	public static boolean isPhone(String value) {
		return value != null && PHONE.matcher(value).matches();
	}

	public static IdentifierType classify(String identifier) {
		if (isEmail(identifier)) return IdentifierType.EMAIL;
		if (isPhone(identifier)) return IdentifierType.PHONE;
		throw new IllegalArgumentException("Identifier must be a valid email or E.164 phone number");
	}
}
