package com.lcd.authenticationapp.repository;

import com.lcd.authenticationapp.models.ERole;
import com.lcd.authenticationapp.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
