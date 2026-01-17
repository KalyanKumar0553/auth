package com.src.main.auth.service;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.src.main.auth.config.OtpConfig;
import com.src.main.auth.exception.OTPException;
import com.src.main.auth.model.Otp;
import com.src.main.auth.model.OtpAttempt;
import com.src.main.auth.model.UserInfo;
import com.src.main.auth.repository.OtpAttemptRepository;
import com.src.main.auth.repository.OtpRepository;
import com.src.main.auth.repository.UserInfoRepository;
import com.src.main.common.util.AppUtils;
import com.src.main.common.util.RequestStatus;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class OTPService {

	private final OtpRepository otpRepository;

	private final OtpAttemptRepository otpAttemptRepository;

	private final UserInfoRepository userRepository;
	
	private final OtpConfig otpConfig;

	public boolean canSendOtp(String username) {
		LocalDateTime startOfToday = LocalDateTime.now().toLocalDate().atStartOfDay();
		LocalDateTime endOfToday = LocalDateTime.now().toLocalDate().atTime(LocalTime.MAX);
		Optional<Otp> latestOTP = otpRepository.findFirstByUsernameAndCreatedAtBetweenOrderByCreatedAtDesc(username,
				startOfToday, endOfToday);
		Optional<OtpAttempt> latestOTPAttempt = otpAttemptRepository
				.findByUsernameAndCreatedAtBetweenOrderByCreatedAtDesc(username, startOfToday, endOfToday);
		if (latestOTPAttempt.isPresent()) {
			if (latestOTPAttempt.get().getAttempts() >= otpConfig.getMaxAttempts()) {
				throw new OTPException(RequestStatus.OTP_LIMIT_EXCEED_ERROR);
			}
			if (latestOTP.isPresent()) {
				LocalDateTime otpSentAt = latestOTP.get().getCreatedAt();
				LocalDateTime nextOtpAt = otpSentAt.plusMinutes(otpConfig.getOtpValiditiyMinutes());
				LocalDateTime currentTime = LocalDateTime.now();

				boolean canSendOTP = nextOtpAt.isBefore(currentTime);
				if (!canSendOTP) {
					throw new OTPException(RequestStatus.OTP_TIME_LIMIT_ERROR,
							AppUtils.formatSecondsToHMString(ChronoUnit.SECONDS.between(currentTime, nextOtpAt)));
				}
			}
		}
		return true;
	}

	public void recordOtpAttempt(String username) {
		LocalDateTime startOfToday = LocalDateTime.now().toLocalDate().atStartOfDay();
		LocalDateTime endOfToday = LocalDateTime.now().toLocalDate().atTime(LocalTime.MAX);
		Optional<OtpAttempt> otpAttemptOpt = otpAttemptRepository
				.findByUsernameAndCreatedAtBetweenOrderByCreatedAtDesc(username, startOfToday, endOfToday);
		if (otpAttemptOpt.isPresent()) {
			OtpAttempt otpAttempt = otpAttemptOpt.get();
			otpAttempt.setAttempts(otpAttempt.getAttempts() + 1);
			otpAttemptRepository.save(otpAttempt);
		} else {
			OtpAttempt otpAttempt = new OtpAttempt();
			otpAttempt.setUsername(username);
			otpAttempt.setCreatedAt(LocalDateTime.now());
			otpAttempt.setAttempts(1);
			otpAttemptRepository.save(otpAttempt);
		}
	}

	public void saveOtp(String username, String otp) {
		Otp otpEntity = new Otp();
		otpEntity.setUsername(username);
		otpEntity.setOtp(otp);
		otpEntity.setCreatedAt(LocalDateTime.now());
		otpRepository.save(otpEntity);
	}

	@Transactional
	public boolean verifyOtp(String username, String otp) {
		Optional<Otp> otpOpt = otpRepository.findFirstByUsernameOrderByCreatedAtDesc(username);
		if (otpOpt.isPresent()) {
			Otp otpEntity = otpOpt.get();
			if (otpEntity.getOtp().equals(otp)) {
				Optional<UserInfo> user = userRepository.findByEmailOrMobile(username, username);
				user.ifPresent(u -> {
					u.setEnabled(true);
					userRepository.save(u);
					otpRepository.deleteAllByUsername(username);
					otpAttemptRepository.deleteAllByUsername(username);
				});
				return true;
			} else {
				throw new OTPException(RequestStatus.OTP_VERIFICATION_FAIL);
			}
		} else {
			throw new OTPException(RequestStatus.OTP_NOT_VERIFIED_ERROR);
		}
	}
}
