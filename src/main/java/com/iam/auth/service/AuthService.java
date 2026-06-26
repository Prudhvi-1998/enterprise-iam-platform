package com.iam.auth.service;

import com.iam.auth.dto.JwtResponse;
import com.iam.auth.dto.LoginRequest;
import com.iam.auth.dto.RegisterRequest;
import com.iam.auth.entity.RefreshToken;
import com.iam.auth.entity.Role;
import com.iam.auth.entity.User;
import com.iam.auth.repository.RoleRepository;
import com.iam.auth.repository.UserRepository;
import com.iam.auth.security.JwtUtils;
import com.iam.auth.service.AuditLogService;
import com.iam.auth.service.RefreshTokenService;
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
    private final RefreshTokenService refreshTokenService;

    public AuthService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager,
                       JwtUtils jwtUtils,
                       AuditLogService auditLogService,
                       RefreshTokenService refreshTokenService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.auditLogService = auditLogService;
        this.refreshTokenService = refreshTokenService;
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

        Role employeeRole = roleRepository.findByName(Role.RoleName.EMPLOYEE)
                .orElseThrow(() -> new RuntimeException("Default role not found"));

        user.getRoles().add((com.iam.auth.entity.Role) employeeRole);
        userRepository.save(user);

        return "User registered successfully";
    }

    public JwtResponse login(LoginRequest request) {

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

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getUsername());

        return new JwtResponse(
                token,
                refreshToken.getToken(),
                user.getUsername(),
                user.getEmail()
        );
    }
}