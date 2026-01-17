package com.src.main.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.src.main.auth.model.Setting;

public interface SettingRepository extends JpaRepository<Setting, String> {
	Optional<Setting> findFirstBySourceAndUsername(String source, String username);
}
