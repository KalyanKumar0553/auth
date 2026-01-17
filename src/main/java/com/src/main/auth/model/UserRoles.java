package com.src.main.auth.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;

@Entity
@Data
public class UserRoles  extends Auditable {

	@Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String userUUID;

    private String roles;

    private long locationID;
}
