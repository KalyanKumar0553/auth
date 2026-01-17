package com.src.main.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.src.main.auth.model.UserRoles;

public interface UserRolesRepository extends JpaRepository<UserRoles, Long> {
	Optional<UserRoles> findByUserUUID(String userID);
}
