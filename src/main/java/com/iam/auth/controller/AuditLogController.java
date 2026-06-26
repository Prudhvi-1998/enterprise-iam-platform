package com.iam.auth.controller;

import com.iam.auth.entity.AuditLog;
import com.iam.auth.service.AuditLogService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/audit")
public class AuditLogController {

    private final AuditLogService auditLogService;

    public AuditLogController(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    // ADMIN only → get all logs
    @GetMapping("/logs")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<AuditLog>> getAllLogs() {
        return ResponseEntity.ok(auditLogService.getAllLogs());
    }

    // ADMIN only → get logs by user id
    @GetMapping("/logs/user/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<AuditLog>> getLogsByUserId(
            @PathVariable Long userId) {
        return ResponseEntity.ok(auditLogService.getLogsByUserId(userId));
    }

    // ADMIN only → get logs by username
    @GetMapping("/logs/username/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<AuditLog>> getLogsByUsername(
            @PathVariable String username) {
        return ResponseEntity.ok(auditLogService.getLogsByUsername(username));
    }

    // ADMIN only → get logs by action
    @GetMapping("/logs/action/{action}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<AuditLog>> getLogsByAction(
            @PathVariable String action) {
        return ResponseEntity.ok(auditLogService.getLogsByAction(action));
    }

    // ADMIN only → get all failed events
    @GetMapping("/logs/failures")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<AuditLog>> getFailedEvents() {
        return ResponseEntity.ok(auditLogService.getFailedEvents());
    }
}