package com.maglione.auth_service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.maglione.auth_service.dto.LoginDto;
import com.maglione.auth_service.exception.InvalidFingerprintException;
import com.maglione.auth_service.exception.JwtAuthenticationException;
import com.maglione.auth_service.models.Role;
import com.maglione.auth_service.models.RoleName;
import com.maglione.auth_service.models.User;
import com.maglione.auth_service.repository.IRoleRepository;
import com.maglione.auth_service.repository.IUserRepository;
import com.maglione.auth_service.security.JwtUtilities;
import com.maglione.auth_service.service.IUserService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import javax.sql.DataSource;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AuthenticationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private IUserService iUserService;

    @Autowired
    private IRoleRepository iRoleRepository;

    @Autowired
    private IUserRepository iUserRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtilities jwtUtilities;

    @Value("${jwt.secret}")
    private String jwtSecret;


    @Test
    void whenValidCredentials_thenReturnJwtTokenAndFingerPrintCookie() throws Exception {
        LoginDto loginDto = new LoginDto();
        loginDto.setEmail("admin@gmail.com");
        loginDto.setPassword("adminPassword");

        mockMvc.perform(post("/user/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginDto)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().exists("Authorization"))
                .andExpect(cookie().exists("FPID"));
    }

    @Test
    void whenInvalidCredentials_thenReturnUnauthorized() throws Exception {
        LoginDto loginDto = new LoginDto();
        loginDto.setEmail("wronguser@gmail.com");
        loginDto.setPassword("wrongpassword");

        mockMvc.perform(post("/user/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginDto)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void whenValidJwtProvided_thenAccessGranted() throws Exception {

        String fingerprint = jwtUtilities.generateFingerprint();
        String token = jwtUtilities.generateToken("admin@gmail.com", List.of("ADMIN"), fingerprint);

        mockMvc.perform(get("/admin/hello")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .cookie(new Cookie("FPID", fingerprint)))  // Simulate fingerprint cookie
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("Hello Admin"));
    }

    @Test
    void whenInvalidJwtProvided_thenAccessForbidden() throws Exception {
        mockMvc.perform(get("/admin/hello")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer invalidToken"))
                .andExpect(status().isForbidden());
    }

    @Test
    void whenNoJwtProvided_thenAccessForbidden() throws Exception {
        mockMvc.perform(get("/admin/hello"))
                .andExpect(status().isForbidden());
    }

    @Test
    void whenInvalidFingerprintProvided_thenReturnInvalidFingerprintException() throws Exception {

        String validFingerprint = jwtUtilities.generateFingerprint();
        String token = jwtUtilities.generateToken("admin@gmail.com", List.of("ADMIN"), validFingerprint);

        String fakeFingerprint = "fakeFingerprint";

        Exception exception = assertThrows(Exception.class, () ->
                mockMvc.perform(get("/admin/hello")  // Endpoint that requires authentication
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                                .cookie(new Cookie("FPID", fakeFingerprint)))  // Fake fingerprint cookie
                        .andExpect(status().isUnauthorized())  // Expecting 401 Unauthorized
        );


        assertNotNull(exception.getCause());
        assertTrue(exception.getCause() instanceof InvalidFingerprintException);
        assertEquals("Fingerprint mismatch detected. Possible session hijacking attempt.",
                exception.getCause().getMessage());

    }

    @Test
    void whenTokenExpired_thenAccessDenied() throws Exception {

        String fingerprint = jwtUtilities.generateFingerprint();

        // Create an expired token manually by setting a past expiration time
        Instant pastTime = Instant.now().minus(1, ChronoUnit.DAYS);
        String expiredToken = Jwts.builder()
                .setSubject("admin@gmail.com")
                .claim("role", List.of("ADMIN"))
                .claim("fingerprint", jwtUtilities.hashFingerprint(fingerprint))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(Date.from(pastTime))
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .compact();


        Exception exception = assertThrows(Exception.class, () ->

                mockMvc.perform(get("/admin/hello")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + expiredToken)
                                .cookie(new Cookie("FPID", fingerprint)))

                        .andExpect(result -> assertTrue(result.getResolvedException() instanceof JwtAuthenticationException))
                        .andExpect(result -> assertEquals("Token expired", result.getResolvedException().getMessage())));


        assertNotNull(exception.getCause());
        assertTrue(exception.getCause() instanceof ExpiredJwtException);

    }


    @BeforeEach
    void setup() {
        // Clean up previous test data
        iUserRepository.deleteAll();
        iRoleRepository.deleteAll();

        // Add roles
        iUserService.saveRole(new Role(RoleName.USER));
        iUserService.saveRole(new Role(RoleName.ADMIN));
        iUserService.saveRole(new Role(RoleName.SUPERADMIN));

        // Add users
        iUserService.saverUser(new User("admin@gmail.com", passwordEncoder.encode("adminPassword"), new ArrayList<>()));
        iUserService.saverUser(new User("superadminadmin@gmail.com", passwordEncoder.encode("superadminPassword"), new ArrayList<>()));

        // Assign ADMIN role to admin user
        Role adminRole = iRoleRepository.findByRoleName(RoleName.ADMIN);
        User adminUser = iUserRepository.findByEmail("admin@gmail.com").orElse(null);
        assertNotNull(adminUser);
        adminUser.getRoles().add(adminRole);
        iUserService.saverUser(adminUser);

        // Assign SUPERADMIN role to superadmin user
        Role superAdminRole = iRoleRepository.findByRoleName(RoleName.SUPERADMIN);
        User superAdminUser = iUserRepository.findByEmail("superadminadmin@gmail.com").orElse(null);
        assertNotNull(superAdminUser);
        superAdminUser.getRoles().add(superAdminRole);
        iUserService.saverUser(superAdminUser);
    }


}
