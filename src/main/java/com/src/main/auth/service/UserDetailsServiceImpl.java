package com.src.main.auth.service;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.thymeleaf.context.Context;

import com.src.main.auth.dto.LoginRequestDTO;
import com.src.main.auth.dto.SignupRequestDTO;
import com.src.main.auth.dto.UserProfileRequestDTO;
import com.src.main.common.exception.AbstractRuntimeException;
import com.src.main.auth.exception.OTPException;
import com.src.main.auth.exception.SignupException;
import com.src.main.auth.exception.UserNotFoundException;
import com.src.main.auth.exception.UserRequestException;
import com.src.main.auth.model.UserInfo;
import com.src.main.auth.model.UserRoles;
import com.src.main.auth.repository.UserInfoRepository;
import com.src.main.auth.repository.UserRolesRepository;
import com.src.main.common.util.AppConstants;
import com.src.main.common.util.AppUtils;
import com.src.main.auth.util.PasswordUtil;
import com.src.main.communication.service.MsgService;
import com.src.main.common.util.RequestStatus;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Service
@Log4j2
@AllArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

	private final UserRolesRepository rolesRepository;

	private final UserInfoRepository userRepository;

	private final MsgService msgService;

	private final OTPService otpService;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserInfo user = userRepository.findByUsername(username)
				.orElseThrow(() -> new UserNotFoundException(RequestStatus.USER_NOT_FOUND));
		return new User(user.getUsername(), user.getPassword(), getAuthorities(user.getUuid()));
	}

	@Transactional
	public UserInfo saveUser(UserInfo user, PasswordEncoder passwordEncoder) {
		try {
			String salt = PasswordUtil.generateSalt();
			user.setSalt(salt);
			String hashPassword = PasswordUtil.hashPassword(user.getPassword(), salt);
			String encodedPassword = passwordEncoder.encode(hashPassword);
			user.setPassword(encodedPassword);
			String otp = generateOtp();
			user.setEnabled(false);
			String userID = generateUUID();
			user.setUuid(userID);
			Context context = new Context();
			context.setVariable("otp", otp);
			sendOTP(user,context);
			return userRepository.save(user);
		} catch(OTPException e ) {
			throw e;
		} catch(Exception e ) {
			e.printStackTrace();
			throw new SignupException(RequestStatus.SIGNUP_ERROR);
		}
	}

	public boolean sendOTP(UserInfo user,Context context) {
		if (otpService.canSendOtp(user.getUsername())) {
//			msgService.sendHtmlEmail("DoNotReply@8fcd10ba-82fa-40fa-88ff-892b2c57d4bd.azurecomm.net",user.getEmail(), "MyComplex : Verification Mail", "otpEmail", context);
			otpService.saveOtp(user.getUsername(), (String)context.getVariable("otp"));
			otpService.recordOtpAttempt(user.getUsername());
			return true;
		} else {
			throw new OTPException(RequestStatus.OTP_SENT_FAIL);
		}
	}

	public String generateOtp() {
		Random random = new Random();
		return String.format("%06d", random.nextInt(999999));
	}

	public Optional<UserInfo> findUserByUsername(String username) {
		return userRepository.findByEmailOrMobile(username, username);
	}

	public boolean verifyOtp(String username,String otp) {
		return otpService.verifyOtp(username, otp);
	}

	public void checkDuplicateUser(SignupRequestDTO signupRequest) {
		if(signupRequest.getEmail()!=null &&  !signupRequest.getEmail().trim().isEmpty()) {
			Optional<UserInfo> userWithEmail = userRepository.findByEmail(signupRequest.getEmail());
			if (userWithEmail.isPresent()) {
				throw new UserRequestException(RequestStatus.USER_DUPLICATE_EMAIL);
			}
		} else {
			throw new UserRequestException(RequestStatus.SIGNUP_REQUEST_EMAIL_DATA_ERROR);
		}
	}

	public Set<GrantedAuthority> getAuthorities(String userUUID) {
		Set<GrantedAuthority> authorities = new HashSet<>();
		authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
		authorities.add(new SimpleGrantedAuthority("USER"));
		Optional<UserRoles> userAdmin = rolesRepository.findByUserUUID(userUUID);
		if(userAdmin.isPresent()) {
			String[] roles = userAdmin.get().getRoles().split(AppConstants.roleSeperator);
			for(String currRole : roles) {
				authorities.add(new SimpleGrantedAuthority(currRole));
			}
		}
		return authorities;
	}

	public UserInfo validateAndGetIfUserEnabled(LoginRequestDTO loginRequest) {
		UserInfo user = findUserByUsername(loginRequest.getEmail())
				.orElseThrow(() -> new UserNotFoundException(RequestStatus.USER_NOT_FOUND));
		if (!user.isEnabled()) {
			String usernameSrc = user.getUsername().equalsIgnoreCase(user.getEmail()) ? "email" : "mobile";
			log.info("usernameSrc : {}", usernameSrc);
			throw new UserNotFoundException(RequestStatus.OTP_NOT_VERIFIED_ERROR, usernameSrc);
		}
		return user;
	}

	private String generateUUID() {
		while(true) {
			List<String> uuidList = AppUtils.generateRandomUUID();
			List<String> existingUserIds = userRepository.findExistingUserIds(uuidList);
			Set<String> existingSet = new HashSet<>(existingUserIds);
	        for (String id : uuidList) {
	            if (!existingSet.contains(id)) {
	                return id;
	            }
	        }
		}
	}

	public void resetPasswordWithOTP(UserInfo user,String otp,String password,PasswordEncoder passwordEncoder) {
		if(verifyOtp(user.getUsername(), otp)) {
			String salt = PasswordUtil.generateSalt();
			user.setSalt(salt);
			String hashPassword = PasswordUtil.hashPassword(password, salt);
			String encodedPassword = passwordEncoder.encode(hashPassword);
			user.setPassword(encodedPassword);
			userRepository.save(user);
		} else {
			throw new AbstractRuntimeException(HttpStatus.BAD_REQUEST.value(),"Error: Failed To Reset Password");
		}

	}

	public void resetPasswordWithoutOTP(UserInfo user,String password,PasswordEncoder passwordEncoder) {
		String salt = PasswordUtil.generateSalt();
		user.setSalt(salt);
		String hashPassword = PasswordUtil.hashPassword(password, salt);
		String encodedPassword = passwordEncoder.encode(hashPassword);
		user.setPassword(encodedPassword);
		userRepository.save(user);
	}

	public void updateUserProfile(UserInfo user, UserProfileRequestDTO profileRequest) {
		user.setFullName(profileRequest.getFullName());
		if(profileRequest.getEmail()!=null) {
			user.setEmail(profileRequest.getEmail());
		} if(profileRequest.getDob()!=null) {
			user.setDob(profileRequest.getDob());
		} if(profileRequest.getFullName()!=null) {
			user.setFullName(profileRequest.getFullName());
		} if(profileRequest.getProfilePic()!=null) {
			user.setProfilePic(profileRequest.getProfilePic());
		}
		userRepository.save(user);
	}
}
