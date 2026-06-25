package com.iam.auth.service;

import com.iam.auth.dto.JwtResponse;
import com.iam.auth.dto.LoginRequest;
import com.iam.auth.dto.RegisterRequest;
import com.iam.auth.entity.User;
import com.iam.auth.repository.RoleRepository;
import com.iam.auth.repository.UserRepository;
import com.iam.auth.security.JwtUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final AuditLogService auditLogService;

    public AuthService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager,
                       JwtUtils jwtUtils,
                       AuditLogService auditLogService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.auditLogService = auditLogService;
    }

    public String register(RegisterRequest request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username is already taken");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email is already registered");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        com.iam.auth.entity.Role employeeRole = roleRepository
                .findByName(com.iam.auth.entity.Role.RoleName.EMPLOYEE)
                .orElseThrow(() -> new RuntimeException(
                        "Default role not found"));

        user.getRoles().add(employeeRole);
        userRepository.save(user);

        // Log the event
        auditLogService.log(
                user.getId(),
                user.getUsername(),
                "REGISTER",
                "/api/auth/register",
                "New user registered: " + user.getUsername(),
                "unknown",
                "SUCCESS"
        );

        return "User registered successfully";
    }

    public JwtResponse login(LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String token = jwtUtils.generateToken(userDetails);

            User user = userRepository.findByUsername(request.getUsername())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Log successful login
            auditLogService.log(
                    user.getId(),
                    user.getUsername(),
                    "LOGIN",
                    "/api/auth/login",
                    "User logged in successfully",
                    "unknown",
                    "SUCCESS"
            );

            return new JwtResponse(token, user.getUsername(), user.getEmail());

        } catch (Exception e) {

            // Log failed login
            auditLogService.log(
                    null,
                    request.getUsername(),
                    "LOGIN",
                    "/api/auth/login",
                    "Failed login attempt: " + e.getMessage(),
                    "unknown",
                    "FAILURE"
            );
            throw e;
        }
    }
}