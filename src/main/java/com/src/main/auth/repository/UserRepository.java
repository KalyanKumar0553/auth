package com.src.main.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.src.main.auth.model.User;

public interface UserRepository extends JpaRepository<User, String> {
	Optional<User> findByIdentifier(String identifier);
}
