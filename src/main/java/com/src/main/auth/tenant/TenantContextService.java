package com.src.main.auth.tenant;

import org.springframework.stereotype.Component;

@Component
public class TenantContextService {
	private final ThreadLocal<TenantConfig> context = new ThreadLocal<>();

	public void setTenant(TenantConfig tenant) {
		context.set(tenant);
	}

	public TenantConfig getTenant() {
		return context.get();
	}

	public void clear() {
		context.remove();
	}
}
