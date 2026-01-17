package com.src.main.auth.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.src.main.auth.model.RolePermissions;

public interface RolesPermissionsRepository extends JpaRepository<RolePermissions, Long> {
	List<RolePermissions> findAllByRoleIn(List<String> role);
}
