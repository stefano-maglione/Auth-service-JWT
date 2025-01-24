package com.maglione.auth_service.repository;

import com.maglione.auth_service.models.Role;
import com.maglione.auth_service.models.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IRoleRepository extends JpaRepository<Role, Integer> {

    Role findByRoleName(RoleName roleName);


}
