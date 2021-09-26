package com.shalunov.cvGenerator.infrastructure.repositories;
import com.shalunov.cvGenerator.domain.Role;
import com.shalunov.cvGenerator.domain.enums.RolesEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
        Optional<Role> findByName(RolesEnum roleName);
}
