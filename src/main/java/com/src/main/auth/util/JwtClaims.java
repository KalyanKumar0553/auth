package com.src.main.auth.util;

import java.util.List;

public class JwtClaims {
	private String sub;
	private String typ;
	private String rid;
	private List<String> roles;
	private String tenantCode;

	public JwtClaims() {}

	public JwtClaims(String sub, String typ, String rid, List<String> roles, String tenantCode) {
		this.sub = sub;
		this.typ = typ;
		this.rid = rid;
		this.roles = roles;
		this.tenantCode = tenantCode;
	}

	public String getSub() {
		return sub;
	}

	public void setSub(String sub) {
		this.sub = sub;
	}

	public String getTyp() {
		return typ;
	}

	public void setTyp(String typ) {
		this.typ = typ;
	}

	public String getRid() {
		return rid;
	}

	public void setRid(String rid) {
		this.rid = rid;
	}

	public List<String> getRoles() {
		return roles;
	}

	public void setRoles(List<String> roles) {
		this.roles = roles;
	}

	public String getTenantCode() {
		return tenantCode;
	}

	public void setTenantCode(String tenantCode) {
		this.tenantCode = tenantCode;
	}
}
