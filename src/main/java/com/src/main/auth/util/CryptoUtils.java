package com.src.main.auth.util;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CryptoUtils {
	private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder(12);
	private static final SecureRandom RANDOM = new SecureRandom();

	private CryptoUtils() {}

	public static String hashPassword(String raw) {
		return ENCODER.encode(raw);
	}

	public static boolean verifyPassword(String raw, String hash) {
		return ENCODER.matches(raw, hash);
	}

	public static String sha256Base64(String value, String key) {
		try {
			if (key != null && !key.isBlank()) {
				Mac mac = Mac.getInstance("HmacSHA256");
				mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
				return Base64.getEncoder().encodeToString(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
			}
			java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
			return Base64.getEncoder().encodeToString(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
		} catch (Exception ex) {
			throw new IllegalStateException("Unable to hash value", ex);
		}
	}

	public static String generateOtp6() {
		int code = RANDOM.nextInt(1_000_000);
		return String.format("%06d", code);
	}

	public static String uuid() {
		return UUID.randomUUID().toString();
	}
}
