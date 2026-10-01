// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** Log-only notifier. Never out of band, so it cannot satisfy the startup channel check. */
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

    @Override
    public void notifyChannelRemoved(String userId, String deviceLabel) {
        log.info("A security-notification registration was removed for {} (device label withheld from logs)",
                userId);
    }
}
