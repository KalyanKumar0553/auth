package com.src.main.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.src.main.auth.model.Role;

public interface RoleRepository extends JpaRepository<Role, String> {}
