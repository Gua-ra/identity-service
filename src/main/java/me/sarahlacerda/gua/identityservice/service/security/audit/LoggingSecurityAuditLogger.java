package me.sarahlacerda.gua.identityservice.service.security.audit;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class LoggingSecurityAuditLogger implements SecurityAuditLogger {

    private static final Logger log = LoggerFactory.getLogger(LoggingSecurityAuditLogger.class);

    @Override
    public void pinInitialized(String userId) {
        log.info("PIN initialized for user {}", userId);
    }

    @Override
    public void pinUpdated(String userId) {
        log.info("PIN updated for user {}", userId);
    }

    @Override
    public void pinValidationSucceeded(String userId) {
        log.debug("PIN validation succeeded for user {}", userId);
    }

    @Override
    public void pinValidationFailed(String userId, int failureCount) {
        log.warn("PIN validation failed for user {} (failureCount={})", userId, failureCount);
    }

    @Override
    public void pinLocked(String userId, Instant lockedUntil) {
        log.warn("PIN locked for user {} until {}", userId, lockedUntil);
    }

    @Override
    public void pinResetRequested(String userId, String maskedPhone, String requesterIp) {
        log.info("PIN reset requested for user {} from IP {} (phone={})", userId, requesterIp, maskedPhone);
    }

    @Override
    public void pinResetCompleted(String userId) {
        log.info("PIN reset completed for user {}", userId);
    }

    @Override
    public void pinChangeStarted(String userId, String maskedPhone, String requesterIp) {
        log.info("PIN change started for user {} from IP {} (phone={})", userId, requesterIp, maskedPhone);
    }

    @Override
    public void pinChangeCompleted(String userId) {
        log.info("PIN change completed for user {}", userId);
    }
}
