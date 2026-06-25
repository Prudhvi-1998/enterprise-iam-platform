package com.iam.auth.service;

import com.iam.auth.entity.AuditLog;
import com.iam.auth.repository.AuditLogRepository;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.List;

@Service
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    public AuditLogService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    // Save a new audit log
    public void log(Long userId, String username, String action,
                    String resource, String details,
                    String ipAddress, String status) {
        AuditLog auditLog = new AuditLog(
                userId, username, action,
                resource, details, ipAddress, status);
        auditLogRepository.save(auditLog);
    }

    // Get all logs
    public List<AuditLog> getAllLogs() {
        return auditLogRepository.findAll();
    }

    // Get logs by user
    public List<AuditLog> getLogsByUserId(Long userId) {
        return auditLogRepository.findByUserId(userId);
    }

    // Get logs by username
    public List<AuditLog> getLogsByUsername(String username) {
        return auditLogRepository.findByUsername(username);
    }

    // Get logs by action
    public List<AuditLog> getLogsByAction(String action) {
        return auditLogRepository.findByAction(action);
    }

    // Get logs between dates
    public List<AuditLog> getLogsBetween(
            LocalDateTime start, LocalDateTime end) {
        return auditLogRepository.findByTimestampBetween(start, end);
    }

    // Get failed events
    public List<AuditLog> getFailedEvents() {
        return auditLogRepository.findByStatus("FAILURE");
    }
}