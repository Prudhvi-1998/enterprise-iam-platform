package com.iam.auth.controller;

import com.iam.auth.dto.JwtResponse;
import com.iam.auth.dto.LoginRequest;
import com.iam.auth.dto.RefreshTokenRequest;
import com.iam.auth.dto.RegisterRequest;
import com.iam.auth.entity.RefreshToken;
import com.iam.auth.service.AuthService;
import com.iam.auth.service.RefreshTokenService;
import com.iam.auth.security.JwtUtils;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;
    private final JwtUtils jwtUtils;
    private final UserDetailsService userDetailsService;

    public AuthController(AuthService authService,
                          RefreshTokenService refreshTokenService,
                          JwtUtils jwtUtils,
                          UserDetailsService userDetailsService) {
        this.authService = authService;
        this.refreshTokenService = refreshTokenService;
        this.jwtUtils = jwtUtils;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @Valid @RequestBody RegisterRequest request) {
        String message = authService.register(request);
        return ResponseEntity.ok(message);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(
            @Valid @RequestBody LoginRequest request) {
        JwtResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<JwtResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {

        RefreshToken refreshToken = refreshTokenService
                .findByToken(request.getRefreshToken())
                .orElseThrow(() -> new RuntimeException(
                        "Refresh token not found"));

        refreshTokenService.verifyExpiration(refreshToken);

        String username = refreshToken.getUser().getUsername();
        UserDetails userDetails = userDetailsService
                .loadUserByUsername(username);
        String newAccessToken = jwtUtils.generateToken(userDetails);

        return ResponseEntity.ok(new JwtResponse(
                newAccessToken,
                refreshToken.getToken(),
                username,
                refreshToken.getUser().getEmail()
        ));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(Authentication authentication) {
        String username = authentication.getName();
        refreshTokenService.deleteByUsername(username);
        return ResponseEntity.ok("Logged out successfully");
    }

    @GetMapping("/me")
    public ResponseEntity<String> getCurrentUser(
            @RequestHeader("Authorization") String token) {
        return ResponseEntity.ok("You are authenticated!");
    }
}