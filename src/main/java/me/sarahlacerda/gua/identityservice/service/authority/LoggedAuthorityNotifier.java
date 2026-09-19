// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * The placeholder notifier, which writes a log line and says so.
 *
 * <p>It exists so the seam has a wiring and the code compiles and runs with the feature off; it is not a
 * channel, and {@link #isOutOfBand()} returns false to say that out loud. A deployment that turns
 * {@code identity.authority.enabled} on with only this bean present fails to start
 * ({@link AuthorityNotificationGate}), which is ADM-009 gate 2 enforced rather than documented.
 *
 * <p>It stays wired when a real notifier is added, because {@link AuthorityNotifications} fans out to
 * every implementation: the operator log line is useful next to a real channel, and it is the only
 * implementation that must never be the reason gate 2 passes.
 */
@Component
public class LoggedAuthorityNotifier implements AuthorityNotifier {

    private static final Logger log = LoggerFactory.getLogger(LoggedAuthorityNotifier.class);

    @Override
    public boolean isOutOfBand() {
        return false;
    }

    @Override
    public void notifyTransitionPending(String userId, String transition, String deviceLabel, Instant effectiveAt) {
        log.info("Authority transition {} pending for {} until {} (device label withheld from logs)",
                transition, userId, effectiveAt);
    }

    @Override
    public void notifyTransitionCancelled(String userId, String transition, String deviceLabel) {
        log.info("Authority transition {} cancelled for {}", transition, userId);
    }

    @Override
    public void notifyTransitionCompleted(String userId, String transition, String deviceLabel) {
        log.info("Authority transition {} completed for {}", transition, userId);
    }
}
