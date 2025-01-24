package com.maglione.auth_service;

import com.maglione.auth_service.models.Role;
import com.maglione.auth_service.models.RoleName;
import com.maglione.auth_service.models.User;
import com.maglione.auth_service.repository.IRoleRepository;
import com.maglione.auth_service.repository.IUserRepository;
import com.maglione.auth_service.service.IUserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;


@SpringBootApplication
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }


    @Bean
    CommandLineRunner run(IUserService iUserService, IRoleRepository iRoleRepository, IUserRepository iUserRepository, PasswordEncoder passwordEncoder) {
        return args ->
        {
            iUserService.saveRole(new Role(RoleName.USER));
            iUserService.saveRole(new Role(RoleName.ADMIN));

            iUserService.saverUser(new User("admin@gmail.com", passwordEncoder.encode("adminPassword"), new ArrayList<>()));

            Role role = iRoleRepository.findByRoleName(RoleName.ADMIN);
            User user = iUserRepository.findByEmail("admin@gmail.com").orElse(null);
            user.getRoles().add(role);
            iUserService.saverUser(user);


        };
    }


}
