package com.src.main.auth.service;

import java.time.Instant;
import java.util.Random;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.src.main.auth.model.CaptchaChallenge;
import com.src.main.auth.repository.CaptchaChallengeRepository;
import com.src.main.auth.util.CryptoUtils;

@Service
public class CaptchaService {
	private final CaptchaChallengeRepository repository;
	private final int ttlSeconds;
	private final Random random = new Random();

	public CaptchaService(
			CaptchaChallengeRepository repository,
			@Value("${captcha.ttl.seconds:300}") int ttlSeconds) {
		this.repository = repository;
		this.ttlSeconds = ttlSeconds;
	}

	public CaptchaResult generate() {
		String answer = randomText(5);
		String id = CryptoUtils.uuid();
		Instant expiresAt = Instant.now().plusSeconds(ttlSeconds);

		CaptchaChallenge challenge = new CaptchaChallenge();
		challenge.setId(id);
		challenge.setAnswerHash(CryptoUtils.sha256Base64(answer.toLowerCase(), null));
		challenge.setExpiresAt(expiresAt);
		challenge.setUsed(false);
		repository.save(challenge);

		String svg = renderSvg(answer);
		String imageBase64 = java.util.Base64.getEncoder().encodeToString(svg.getBytes(java.nio.charset.StandardCharsets.UTF_8));
		return new CaptchaResult(id, imageBase64);
	}

	public void verify(String captchaId, String captchaText) {
		if (captchaId == null || captchaText == null) {
			throw new IllegalArgumentException("Captcha is required");
		}
		CaptchaChallenge challenge = repository.findById(captchaId).orElseThrow(() -> new IllegalArgumentException("Invalid captcha"));
		if (challenge.isUsed()) {
			throw new IllegalArgumentException("Captcha already used");
		}
		if (challenge.getExpiresAt().isBefore(Instant.now())) {
			throw new IllegalArgumentException("Captcha expired");
		}

		String expected = CryptoUtils.sha256Base64(captchaText.trim().toLowerCase(), null);
		if (!expected.equals(challenge.getAnswerHash())) {
			throw new IllegalArgumentException("Captcha mismatch");
		}
		challenge.setUsed(true);
		repository.save(challenge);
	}

	private String randomText(int len) {
		String chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
		StringBuilder out = new StringBuilder();
		for (int i = 0; i < len; i++) {
			out.append(chars.charAt(random.nextInt(chars.length())));
		}
		return out.toString();
	}

	private String renderSvg(String text) {
		StringBuilder noise = new StringBuilder();
		for (int i = 0; i < 18; i++) {
			int x1 = random.nextInt(220);
			int y1 = random.nextInt(70);
			int x2 = random.nextInt(220);
			int y2 = random.nextInt(70);
			int sw = 1 + random.nextInt(2);
			noise.append("<line x1=\"").append(x1).append("\" y1=\"").append(y1)
					.append("\" x2=\"").append(x2).append("\" y2=\"").append(y2)
					.append("\" stroke=\"#777\" stroke-width=\"").append(sw)
					.append("\" opacity=\"0.35\"/>");
		}

		StringBuilder jitter = new StringBuilder();
		for (int i = 0; i < text.length(); i++) {
			char ch = text.charAt(i);
			int x = 30 + i * 35 + random.nextInt(6);
			int y = 45 + random.nextInt(8);
			int r = -12 + random.nextInt(24);
			jitter.append("<text x=\"").append(x).append("\" y=\"").append(y)
					.append("\" font-size=\"34\" font-family=\"Verdana\" fill=\"#222\" transform=\"rotate(")
					.append(r).append(" ").append(x).append(" ").append(y).append(")\">")
					.append(ch).append("</text>");
		}

		return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
				"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"240\" height=\"80\" viewBox=\"0 0 240 80\">" +
				"<rect width=\"240\" height=\"80\" rx=\"10\" ry=\"10\" fill=\"#f3f3f3\"/>" +
				noise + jitter + "</svg>";
	}

	public record CaptchaResult(String captchaId, String imageBase64) {}
}
