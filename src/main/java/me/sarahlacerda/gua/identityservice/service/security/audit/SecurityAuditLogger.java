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

    void pinChangeStarted(String userId, String maskedPhone, String requesterIp);

    void pinChangeCompleted(String userId);

    /**
     * A change-number OTP was successfully requested for {@code userId} (the new
     * number's OTP SMS is on its way). {@code maskedNewPhone} is the display-only
     * masked target (e.g. {@code ••••4567}) — never the plaintext E.164.
     */
    void phoneChangeRequested(String userId, String maskedNewPhone, String ip);

    /**
     * A change-number request was blocked by the fresh-2FA (post-PIN-write)
     * cooldown. Emitted on every blocked retry so support sees the full trail.
     * {@code maskedNewPhone} is the display-only masked target — never plaintext.
     */
    void phoneChangeCooldownBlocked(String userId, String maskedNewPhone, long cooldownSeconds, String ip);

    /**
     * A change-number completed: the account was atomically rebound to the new
     * number. Both phones are display-only masked — never plaintext E.164.
     */
    void phoneChangeCompleted(String userId, String maskedOldPhone, String maskedNewPhone);
}
