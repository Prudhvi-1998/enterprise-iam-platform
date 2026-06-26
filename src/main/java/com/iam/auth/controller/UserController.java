package com.iam.auth.controller;

import com.iam.auth.dto.UpdateUserRequest;
import com.iam.auth.dto.UserResponse;
import com.iam.auth.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    // ADMIN + MANAGER → get all users
    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    // ADMIN + MANAGER → get user by id
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<UserResponse> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(userService.getUserById(id));
    }

    // ALL roles → get own profile
    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserResponse> getMyProfile(
            Authentication authentication) {
        String username = authentication.getName();
        return ResponseEntity.ok(userService.getUserByUsername(username));
    }

    // ADMIN + MANAGER → update user
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<UserResponse> updateUser(
            @PathVariable Long id,
            @RequestBody UpdateUserRequest request,
            Authentication authentication) {
        String updatedBy = authentication.getName();
        return ResponseEntity.ok(userService.updateUser(id, request, updatedBy));
    }

    // ADMIN only → assign roles
    @PutMapping("/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserResponse> assignRoles(
            @PathVariable Long id,
            @RequestBody Set<String> roles,
            Authentication authentication) {
        String assignedBy = authentication.getName();
        return ResponseEntity.ok(userService.assignRoles(id, roles, assignedBy));
    }

    // ADMIN only → delete user
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> deleteUser(
            @PathVariable Long id,
            Authentication authentication) {
        String deletedBy = authentication.getName();
        userService.deleteUser(id, deletedBy);
        return ResponseEntity.ok("User deleted successfully");
    }
}