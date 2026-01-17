package com.src.main.auth.filter;

import java.io.IOException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.src.main.auth.config.JWTTokenProvider;
import com.src.main.auth.service.UserDetailsServiceImpl;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private JWTTokenProvider jwtTokenProvider;

	private UserDetailsServiceImpl userDetailsService;

	public JwtAuthenticationFilter(JWTTokenProvider jwtTokenProvider, UserDetailsServiceImpl userDetailsService) {
		this.jwtTokenProvider = jwtTokenProvider;
		this.userDetailsService = userDetailsService;
	}


	private String getJWTFromRequest(HttpServletRequest request) {
		String bearerToken = request.getHeader("Authorization");
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
			return bearerToken.substring(7);
		}
		return null;
	}


	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String token = getJWTFromRequest(request);

		if (StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)) {
            
			String username = jwtTokenProvider.getUsernameFromJWT(token);
            List<String> roles = jwtTokenProvider.getRolesFromJWT(token);
            Claims claims = jwtTokenProvider.extractAllClaims(token);
            Date expiration = claims.getExpiration();
            
            if (expiration != null) {
        		DateTimeFormatter formatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
        		String formatted = expiration.toInstant().atZone(ZoneId.systemDefault()).format(formatter);
        		response.setHeader("X-Token-Expires-At", formatted);
            }
            List<GrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
            UserDetails userDetails = new User(username, "", authorities);

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
            
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
	}
}
