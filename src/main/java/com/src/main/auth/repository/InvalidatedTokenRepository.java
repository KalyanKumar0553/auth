package com.src.main.auth.repository;

import java.time.LocalDateTime;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.src.main.auth.model.InvalidatedToken;

@Repository
public interface InvalidatedTokenRepository extends JpaRepository<InvalidatedToken, Long> {

    boolean existsByToken(String token);

    @Modifying
    @Query("DELETE FROM InvalidatedToken t WHERE t.expirationDate <= :now")
    void deleteAllExpiredTokens(LocalDateTime now);
    
}
