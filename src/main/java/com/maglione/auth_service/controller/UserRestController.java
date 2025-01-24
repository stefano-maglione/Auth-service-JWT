package com.maglione.auth_service.controller;


import com.maglione.auth_service.dto.LoginDto;
import com.maglione.auth_service.dto.RegisterDto;
import com.maglione.auth_service.service.IUserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserRestController {


    private final IUserService iUserService;

    //http://localhost:8087/api/user/register
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterDto registerDto) {
        return iUserService.register(registerDto);
    }

    //http://localhost:8087/api/user/authenticate
    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody LoginDto loginDto) {
        return iUserService.authenticate(loginDto);
    }

    //RessourceEndPoint:http://localhost:8087/api/user/hi
    @GetMapping("/hi")
    public String sayHi() {
        return "Hi User";
    }

}
