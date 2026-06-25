package com.iam.auth.repository;

import com.iam.auth.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    // Find all logs for a specific user
    List<AuditLog> findByUserId(Long userId);

    // Find all logs for a specific username
    List<AuditLog> findByUsername(String username);

    // Find all logs for a specific action
    List<AuditLog> findByAction(String action);

    // Find logs between two timestamps
    List<AuditLog> findByTimestampBetween(
            LocalDateTime start, LocalDateTime end);

    // Find logs by status
    List<AuditLog> findByStatus(String status);
}