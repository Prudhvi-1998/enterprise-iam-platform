package com.iam.auth.service;

import com.iam.auth.dto.UpdateUserRequest;
import com.iam.auth.dto.UserResponse;
import com.iam.auth.entity.Role;
import com.iam.auth.entity.User;
import com.iam.auth.repository.RoleRepository;
import com.iam.auth.repository.UserRepository;
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

    public List<UserResponse> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(UserResponse::fromUser)
                .collect(Collectors.toList());
    }

    public UserResponse getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return UserResponse.fromUser(user);
    }

    public UserResponse getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return UserResponse.fromUser(user);
    }

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

        // Log the event
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

        // Log the event
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

    public void deleteUser(Long id, String deletedBy) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Log before deleting
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