// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Instant;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * A notifier that throws is logged and swallowed: a transport failure must not roll back an accepted
 * transition.
 */
@Service
public class AuthorityNotifications {

    private static final Logger log = LoggerFactory.getLogger(AuthorityNotifications.class);

    private final List<AuthorityNotifier> notifiers;

    public AuthorityNotifications(List<AuthorityNotifier> notifiers) {
        this.notifiers = List.copyOf(notifiers);
    }

    public boolean hasOutOfBandChannel() {
        return notifiers.stream().anyMatch(AuthorityNotifier::isOutOfBand);
    }

    public boolean reachesOutOfBandChannel(String userId) {
        return notifiers.stream().anyMatch(notifier -> notifier.reachesOutOfBand(userId));
    }

    public void pending(String userId, String transition, String deviceLabel, Instant effectiveAt) {
        each(notifier -> notifier.notifyTransitionPending(userId, transition, deviceLabel, effectiveAt));
    }

    public void cancelled(String userId, String transition, String deviceLabel) {
        each(notifier -> notifier.notifyTransitionCancelled(userId, transition, deviceLabel));
    }

    public void completed(String userId, String transition, String deviceLabel) {
        each(notifier -> notifier.notifyTransitionCompleted(userId, transition, deviceLabel));
    }

    public void channelRemoved(String userId, String deviceLabel) {
        each(notifier -> notifier.notifyChannelRemoved(userId, deviceLabel));
    }

    private void each(java.util.function.Consumer<AuthorityNotifier> action) {
        for (AuthorityNotifier notifier : notifiers) {
            try {
                action.accept(notifier);
            } catch (RuntimeException ex) {
                log.error("An authority notification channel failed: {}", ex.getMessage());
            }
        }
    }
}
