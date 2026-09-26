package me.sarahlacerda.gua.identityservice.service.security.audit;

import java.time.Instant;

public interface SecurityAuditLogger {

    void pinInitialized(String userId);

    void pinUpdated(String userId);

    void pinValidationSucceeded(String userId);

    void pinValidationFailed(String userId, int failureCount);

    void pinLocked(String userId, Instant lockedUntil);

    void accountRecoveryRequested(String userId, String maskedPhone, String requesterIp);

    void accountRecoveryCompleted(String userId, int passkeysRemoved);

    void accountRecoveryCancelled(String userId, String requesterIp);

    void pinChangeStarted(String userId, String maskedPhone, String requesterIp);

    void pinChangeCompleted(String userId);

    void phoneChangeStarted(String userId, String maskedOldPhone, String maskedNewPhone, String requesterIp);

    void phoneChangeCompleted(String userId, String maskedNewPhone);

    void phoneChangeOtpFailed(String userId, int attempt, String requesterIp);

    void reauthFailed(String userId, String operation, String requesterIp);

    /**
     * An authority transition this service accepted (ADM-009).
     *
     * <p>Its own entry, because it was reported through {@link #reauthFailed} and read as one: every
     * accepted adoption, grant, revocation and recovery was written to the audit trail as "Reauth/step-up
     * failed", at WARN. That inverts the record a security review reads to find out what happened to an
     * account, and it buried real step-up failures among successes.
     *
     * @param pending false when the transition took effect at once, true while its window is running.
     */
    void authorityTransitionAccepted(String userId, String type, long seq, boolean pending, Instant effectiveAt);
}
