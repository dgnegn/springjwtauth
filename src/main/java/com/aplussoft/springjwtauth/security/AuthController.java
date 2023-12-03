package com.aplussoft.springjwtauth.security;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.aplussoft.springjwtauth.dto.AuthRequest;
import com.aplussoft.springjwtauth.model.Role;
import com.aplussoft.springjwtauth.model.User;
import com.aplussoft.springjwtauth.repository.UserRepository;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;

@AllArgsConstructor
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final AuthenticationProvider authenticationProvider;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@Valid @RequestBody User user) {

        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException(String.format("User %s already exists!", user.getEmail()));
        }

        var newUser = User
                .builder()
                .email(user.getEmail())
                .firstname(user.getFirstname())
                .lastname(user.getLastname())
                .password(passwordEncoder.encode(user.getPassword()))
                .role(userRepository.count() == 0 ? Role.ADMIN : Role.USER)
                .build();

        userRepository.save(newUser);
        String generatedToken = jwtUtils.generateJwt(user);

        AuthResponse response = new AuthResponse();        
        response.setToken(generatedToken);

        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthResponse> signin(@Valid @RequestBody AuthRequest authRequest) {

        try {
            authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(
                    authRequest.getEmail(), authRequest.getPassword()));

            var userAuthenticated = userRepository.findByEmail(authRequest.getEmail()).orElseThrow();

            String generetedToken = jwtUtils.generateJwt(userAuthenticated);

            AuthResponse authResponse = new AuthResponse();
            authResponse.setToken(generetedToken);
            return ResponseEntity.status(HttpStatus.OK).body(authResponse);
        } catch (org.springframework.security.core.AuthenticationException ex) {
            throw new RuntimeException(ex.getMessage());
        }

    }
}
