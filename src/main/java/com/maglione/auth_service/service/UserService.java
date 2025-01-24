package com.maglione.auth_service.service;

import com.maglione.auth_service.dto.LoginDto;
import com.maglione.auth_service.dto.RegisterDto;
import com.maglione.auth_service.models.Role;
import com.maglione.auth_service.models.RoleName;
import com.maglione.auth_service.models.User;
import com.maglione.auth_service.repository.IRoleRepository;
import com.maglione.auth_service.repository.IUserRepository;
import com.maglione.auth_service.security.JwtUtilities;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.owasp.encoder.Encode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


@Service
@Transactional
@RequiredArgsConstructor
public class UserService implements IUserService {

    private final AuthenticationManager authenticationManager;
    private final IUserRepository iUserRepository;
    private final IRoleRepository iRoleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtilities jwtUtilities;
    @Value("${jwt.expiration}")
    private Long jwtExpiration;


    @Override
    public Role saveRole(Role role) {
        return iRoleRepository.save(role);
    }

    @Override
    public User saverUser(User user) {
        return iUserRepository.save(user);
    }

    @Override
    public ResponseEntity<?> register(RegisterDto registerDto) {
        if (iUserRepository.existsByEmail(registerDto.getEmail())) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Collections.singletonMap("message", "Email is already taken!"));
        } else {
            User user = new User();
            user.setEmail(Encode.forHtml(registerDto.getEmail().trim()));
            user.setFirstName(Encode.forHtml(registerDto.getFirstName().trim()));
            user.setLastName(registerDto.getLastName().trim());
            user.setPassword(passwordEncoder.encode(registerDto.getPassword().trim()));
            //By Default , he/she is a simple user
            Role role = iRoleRepository.findByRoleName(RoleName.USER);
            user.setRoles(Collections.singletonList(role));
            iUserRepository.save(user);
            return ResponseEntity.ok(Collections.singletonMap("message", "User registered successfully"));

        }
    }

    @Override
    public ResponseEntity<?> authenticate(LoginDto loginDto) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        Encode.forHtml(loginDto.getEmail().trim()),
                        Encode.forHtml(loginDto.getPassword().trim())
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        User user = iUserRepository.findByEmail(authentication.getName()).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        List<String> rolesNames = new ArrayList<>();
        user.getRoles().forEach(r -> rolesNames.add(r.getRoleName()));
        String fingerprint = jwtUtilities.generateFingerprint();
        String token = jwtUtilities.generateToken(user.getUsername(), rolesNames, fingerprint);

        // Set the fingerprint as a secure hardened cookie
        ResponseCookie fingerprintCookie = ResponseCookie.from("FPID", fingerprint)
                .httpOnly(true)  // Prevent JavaScript access (mitigate XSS)
                .secure(false)    // Only allow over HTTPS
                .sameSite("Strict")  // Prevent CSRF attacks
                .maxAge(jwtExpiration / 1000)  // Max age should be <= JWT expiry (in seconds)
                .path("/")  // Available across entire domain
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, fingerprintCookie.toString())
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();

    }

}
