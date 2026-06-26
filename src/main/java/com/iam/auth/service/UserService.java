package com.iam.auth.service;

import com.iam.auth.dto.UpdateUserRequest;
import com.iam.auth.dto.UserResponse;
import com.iam.auth.entity.Role;
import com.iam.auth.entity.User;
import com.iam.auth.repository.RoleRepository;
import com.iam.auth.repository.UserRepository;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditLogService auditLogService;

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder,
                       AuditLogService auditLogService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditLogService = auditLogService;
    }

    // Get all users
    @Cacheable(value = "allUsers")
    public List<UserResponse> getAllUsers() {
        System.out.println("Loading ALL users from DATABASE");
        return userRepository.findAll()
                .stream()
                .map(UserResponse::fromUser)
                .collect(Collectors.toList());
    }

    // Get user by id
    @Cacheable(value = "users", key = "#id")
    public UserResponse getUserById(Long id) {
        System.out.println("Loading user from DATABASE: " + id);
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return UserResponse.fromUser(user);
    }

    // Get user by username
    @Cacheable(value = "users", key = "#username")
    public UserResponse getUserByUsername(String username) {
        System.out.println("Loading user from DATABASE: " + username);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return UserResponse.fromUser(user);
    }

    // Update user - invalidate cache
    @CacheEvict(value = {"users", "allUsers", "userDetails"}, allEntries = true)
    public UserResponse updateUser(Long id, UpdateUserRequest request,
                                   String updatedBy) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (request.getEmail() != null) {
            user.setEmail(request.getEmail());
        }
        if (request.getPassword() != null) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }
        if (request.getStatus() != null) {
            user.setStatus(User.UserStatus.valueOf(request.getStatus()));
        }

        userRepository.save(user);

        auditLogService.log(
                user.getId(),
                updatedBy,
                "UPDATE_USER",
                "/api/users/" + id,
                "User updated: " + user.getUsername() + " by " + updatedBy,
                "unknown",
                "SUCCESS"
        );

        return UserResponse.fromUser(user);
    }

    // Assign roles - invalidate cache
    @CacheEvict(value = {"users", "allUsers", "userDetails"}, allEntries = true)
    public UserResponse assignRoles(Long id, Set<String> roleNames,
                                    String assignedBy) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Set<com.iam.auth.entity.Role> roles = roleNames.stream()
                .map(roleName -> roleRepository
                        .findByName(Role.RoleName.valueOf(roleName))
                        .orElseThrow(() -> new RuntimeException(
                                "Role not found: " + roleName)))
                .collect(Collectors.toSet());

        user.setRoles(roles);
        userRepository.save(user);

        auditLogService.log(
                user.getId(),
                assignedBy,
                "ASSIGN_ROLE",
                "/api/users/" + id + "/roles",
                "Roles assigned to " + user.getUsername()
                        + ": " + roleNames + " by " + assignedBy,
                "unknown",
                "SUCCESS"
        );

        return UserResponse.fromUser(user);
    }

    // Delete user - invalidate cache
    @CacheEvict(value = {"users", "allUsers", "userDetails"}, allEntries = true)
    public void deleteUser(Long id, String deletedBy) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        auditLogService.log(
                user.getId(),
                deletedBy,
                "DELETE_USER",
                "/api/users/" + id,
                "User deleted: " + user.getUsername() + " by " + deletedBy,
                "unknown",
                "SUCCESS"
        );

        userRepository.delete(user);
    }
}