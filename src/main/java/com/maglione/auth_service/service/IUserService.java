package com.maglione.auth_service.service;

import com.maglione.auth_service.dto.LoginDto;
import com.maglione.auth_service.dto.RegisterDto;
import com.maglione.auth_service.models.Role;
import com.maglione.auth_service.models.User;
import org.springframework.http.ResponseEntity;


public interface IUserService {

    ResponseEntity<?> authenticate(LoginDto loginDto);

    ResponseEntity<?> register(RegisterDto registerDto);

    Role saveRole(Role role);

    User saverUser(User user);
}
