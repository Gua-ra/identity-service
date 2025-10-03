package me.sarahlacerda.gua.identityservice.service.security.audit;

import java.time.Instant;

public interface SecurityAuditLogger {

    void pinInitialized(String userId);

    void pinUpdated(String userId);

    void pinValidationSucceeded(String userId);

    void pinValidationFailed(String userId, int failureCount);

    void pinLocked(String userId, Instant lockedUntil);

    void pinResetRequested(String userId, String maskedPhone, String requesterIp);

    void pinResetCompleted(String userId);
}
