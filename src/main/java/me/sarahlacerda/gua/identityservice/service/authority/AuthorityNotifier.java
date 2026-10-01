// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Instant;

public interface AuthorityNotifier {

    /**
     * True only for a channel that neither a SIM swap nor an account recovery can empty. A log line, an SMS
     * and a signed-in session do not qualify.
     */
    boolean isOutOfBand();

    /** The per-account form of {@link #isOutOfBand()}: true only while this account has a live destination. */
    default boolean reachesOutOfBand(String userId) {
        return false;
    }

    void notifyTransitionPending(String userId, String transition, String deviceLabel, Instant effectiveAt);

    void notifyTransitionCancelled(String userId, String transition, String deviceLabel);

    void notifyTransitionCompleted(String userId, String transition, String deviceLabel);

    default void notifyChannelRemoved(String userId, String deviceLabel) {
    }
}
