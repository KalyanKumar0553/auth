package com.src.main.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.src.main.auth.model.UserProfile;

public interface UserProfileRepository extends JpaRepository<UserProfile, String> {}
