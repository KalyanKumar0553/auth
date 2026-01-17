package com.src.main.auth.model;

import java.io.Serializable;
import java.util.Objects;

public class UserRoleId implements Serializable {
	private String userId;
	private String roleName;

	public UserRoleId() {}

	public UserRoleId(String userId, String roleName) {
		this.userId = userId;
		this.roleName = roleName;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		UserRoleId that = (UserRoleId) o;
		return Objects.equals(userId, that.userId) && Objects.equals(roleName, that.roleName);
	}

	@Override
	public int hashCode() {
		return Objects.hash(userId, roleName);
	}
}
