package com.src.main.auth.service;

import java.util.Optional;

import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

public class AuditorAwareService implements AuditorAware<String> {

    @Override
    public Optional<String> getCurrentAuditor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return Optional.of("SYSTEM");
        }
        for(GrantedAuthority currAuthority : auth.getAuthorities()) {
        	if(currAuthority.getAuthority().equalsIgnoreCase("ROLE_ANONYMOUS")) {
        		return Optional.of("SYSTEM");
        	}
        }
        return Optional.ofNullable(auth.getName());
    }
}