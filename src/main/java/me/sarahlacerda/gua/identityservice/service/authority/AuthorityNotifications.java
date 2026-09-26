// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Instant;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Every wired {@link AuthorityNotifier}, and the one question ADM-009 gate 2 asks of them as a set.
 *
 * <p>A composite rather than a single bean, because the operator log line is worth keeping next to a real
 * channel and because "is there a channel at all" is a property of the set, not of any one implementation.
 * A notification that throws is logged and swallowed: a transport being down must not roll back a
 * transition that was already accepted, and it must not stop the account holder being told on the other
 * channels.
 */
@Service
public class AuthorityNotifications {

    private static final Logger log = LoggerFactory.getLogger(AuthorityNotifications.class);

    private final List<AuthorityNotifier> notifiers;

    public AuthorityNotifications(List<AuthorityNotifier> notifiers) {
        this.notifiers = List.copyOf(notifiers);
    }

    /**
     * Whether at least one wired notifier reaches the account holder on a channel that neither a SIM swap
     * nor an account recovery empties. This is the whole of gate 2.
     */
    public boolean hasOutOfBandChannel() {
        return notifiers.stream().anyMatch(AuthorityNotifier::isOutOfBand);
    }

    /**
     * Whether at least one wired notifier reaches <em>this</em> account holder out of band right now.
     *
     * <p>Asked before a record that starts a window is accepted. The deployment-level question above is what
     * the startup gate needs; this is what the account holder needs, and the two differ for exactly the
     * account that matters: one that has never registered an install has no channel however well the
     * deployment is configured, so its window would run unwitnessed.
     */
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

    /** One of the account's own channels was removed, announced to the ones that are left. */
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
