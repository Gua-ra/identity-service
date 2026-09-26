// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration.Platform;

/**
 * One way of reaching an install (ADM-009 gate 2).
 *
 * <p>An interface rather than two methods on the notifier so the notifier holds no transport detail and a
 * test can wire a transport that records what it was asked to send. The payload is already reduced to what a
 * notification may say by the time it arrives here: a label, a sentence and a time.
 */
public interface AuthorityPushTransport {

    /**
     * The key both transports put in the payload beside the alert, so a client can tell one of these from a
     * room notification and show it itself.
     *
     * <p>It exists because the alert was invisible in the case it matters most. Both push services hand a
     * message to a foregrounded app rather than to the notification tray, and both clients route what they
     * receive through a handler that expects a Matrix push and discards anything else. So an owner looking
     * at their phone, which is exactly who a "something is asking for authority over your account" alert is
     * for, saw nothing at all. Seen on a real device on dev: the message arrived two seconds after the
     * transition was accepted and was dropped as "Invalid data received".
     */
    String ALERT_MARKER = "gua_authority_alert";

    /** Which registrations this transport addresses. */
    Platform platform();

    /**
     * Whether this transport holds what it needs to send.
     *
     * <p>False until a deployment configures its credential, which is what keeps gate 2 blocking: a notifier
     * with no configured transport is not a channel, and says so.
     */
    boolean isConfigured();

    /**
     * Sends one alert, or reports that the destination is permanently gone.
     *
     * @param token the destination as the install registered it, never logged
     * @param appId the app id the install sent, which picks the topic or the project
     * @param title short, and free of anything the account holder did not already name
     * @param body  the transition in the reader's own words, plus when it completes
     * @return {@link Outcome#DELIVERED}, {@link Outcome#RETRYABLE} or {@link Outcome#UNREGISTERED}
     */
    Outcome send(String token, String appId, String title, String body);

    /** What the transport learned about the destination. */
    enum Outcome {
        /** Accepted by the push service. */
        DELIVERED,
        /** A transient failure. The registration keeps counting as a channel. */
        RETRYABLE,
        /** The destination is gone for good, so the registration stops counting as a channel. */
        UNREGISTERED
    }
}
