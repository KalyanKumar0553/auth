package com.src.main.auth.security;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import com.src.main.auth.model.Tenant;
import com.src.main.auth.model.TenantShaKey;
import com.src.main.auth.repository.TenantRepository;
import com.src.main.auth.repository.TenantShaKeyRepository;
import com.src.main.auth.tenant.TenantConfig;
import com.src.main.auth.tenant.TenantContextService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class TenantContextFilter extends OncePerRequestFilter {
	private final TenantRepository tenantRepository;
	private final TenantShaKeyRepository shaKeyRepository;
	private final TenantContextService tenantContext;
	private final String headerName;

	public TenantContextFilter(
			TenantRepository tenantRepository,
			TenantShaKeyRepository shaKeyRepository,
			TenantContextService tenantContext,
			String headerName) {
		this.tenantRepository = tenantRepository;
		this.shaKeyRepository = shaKeyRepository;
		this.tenantContext = tenantContext;
		this.headerName = headerName.toLowerCase();
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			String path = request.getRequestURI();
			String tenantCode = extractTenantCode(request);
			boolean required = path.startsWith("/api/v1/auth") || path.startsWith("/api/v1/tenant");
			if (required && (tenantCode == null || tenantCode.isBlank())) {
				response.sendError(HttpStatus.BAD_REQUEST.value(), "Missing tenantCode");
				return;
			}
			if (tenantCode != null && !tenantCode.isBlank()) {
				Tenant tenant = tenantRepository.findByTenantCode(tenantCode.trim())
						.orElse(null);
				if (tenant == null) {
					response.sendError(HttpStatus.BAD_REQUEST.value(), "Invalid tenantCode");
					return;
				}
				if (!tenant.isActive()) {
					response.sendError(HttpStatus.FORBIDDEN.value(), "Tenant is inactive");
					return;
				}
				TenantShaKey shaKey = shaKeyRepository
						.findFirstByTenantIdAndIsActiveTrueOrderByCreatedAtDesc(tenant.getId())
						.orElse(null);
				String key = shaKey != null ? shaKey.getShaKey() : null;
				tenantContext.setTenant(new TenantConfig(
						tenant.getId(), tenant.getTenantCode(), tenant.getDisplayName(), tenant.isActive(), key));
			}
			filterChain.doFilter(request, response);
		} finally {
			tenantContext.clear();
		}
	}

	private String extractTenantCode(HttpServletRequest request) {
		String headerValue = request.getHeader(headerName);
		if (headerValue != null) {
			return headerValue;
		}
		String param = request.getParameter("tenantCode");
		return param;
	}
}
