package com.maglione.auth_service.security;

import com.maglione.auth_service.models.User;
import com.maglione.auth_service.repository.IUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;


@Component
@RequiredArgsConstructor
public class CustomerUserDetailsService implements UserDetailsService {

    private final IUserRepository iUserRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = iUserRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found !"));
        return user;

    }


}
