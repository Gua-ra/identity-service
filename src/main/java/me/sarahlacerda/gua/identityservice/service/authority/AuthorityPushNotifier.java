// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration;

/**
 * The channel ADM-009 gate 2 asks for: a registration this service owns, delivered straight to APNs or FCM.
 *
 * <p><b>Why {@link #isOutOfBand()} may answer true here.</b> The two channels gate 2 rejects fail for
 * specific reasons, and this one fails neither. It is not the account's phone number, so a SIM swap does not
 * hold it. It is not a session, so the sign-out an account recovery performs does not empty it: the row is
 * keyed on an installation id the client keeps in its keychain or keystore, and
 * {@code AccountRecoveryService.complete} writes {@code identity_users} and {@code passkey_credentials} only,
 * while the session revocation runs in another service against another database. Neither can reach this table
 * even by mistake, which is what {@code AuthorityNotificationSurvivesRecoveryTest} drives and asserts against
 * the shipped recovery path rather than a mock.
 *
 * <p>It answers true only when a transport is actually configured. A deployment that turns the chain on
 * without an APNs or FCM credential still fails to start, because a bean that could not send anything is not
 * a channel however it is wired.
 *
 * <p>{@link #reachesOutOfBand(String)} is the per-account half, and it is the one a transition consults: gate
 * 2 is a claim that <em>this</em> account holder will be told, and an account with no live registration has
 * no such claim behind it. The single-install case is the honest residual: there the only registration is the
 * install performing the transition, so on a stolen unlocked phone the alert reaches the thief. That is not
 * closed here and the README says so.
 *
 * <p>A send that fails is logged and swallowed by {@link AuthorityNotifications}, so a transport being down
 * never rolls back a record the chain has already accepted.
 */
@Component
public class AuthorityPushNotifier implements AuthorityNotifier {

    private static final Logger log = LoggerFactory.getLogger(AuthorityPushNotifier.class);

    private static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("d MMM HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    private final AuthorityNotificationRegistry registry;
    private final List<AuthorityPushTransport> transports;
    private final AuthorityPolicy policy;
    private final Clock clock;

    public AuthorityPushNotifier(AuthorityNotificationRegistry registry, List<AuthorityPushTransport> transports,
            AuthorityPolicy policy, Clock clock) {
        this.registry = registry;
        this.transports = List.copyOf(transports);
        this.policy = policy;
        this.clock = clock;
    }

    @Override
    public boolean isOutOfBand() {
        return policy.notificationsEnabled() && transports.stream().anyMatch(AuthorityPushTransport::isConfigured);
    }

    @Override
    public boolean reachesOutOfBand(String userId) {
        return isOutOfBand() && StringUtils.hasText(userId)
                && !registry.live(userId, clock.instant()).isEmpty();
    }

    @Override
    public void notifyTransitionPending(String userId, String transition, String deviceLabel, Instant effectiveAt) {
        // The only three things a notification may carry: what was started, which device it names, and when it
        // completes. No room, no message, no phone number, no account identifier.
        send(userId, "Check this was you", sentence(transition, deviceLabel)
                + " It completes on " + WHEN.format(effectiveAt) + " unless you say no in the app.");
    }

    @Override
    public void notifyTransitionCancelled(String userId, String transition, String deviceLabel) {
        send(userId, "That was stopped", sentence(transition, deviceLabel) + " It has been cancelled.");
    }

    @Override
    public void notifyTransitionCompleted(String userId, String transition, String deviceLabel) {
        send(userId, "That has taken effect", sentence(transition, deviceLabel) + " It is now in effect.");
    }

    @Override
    public void notifyChannelRemoved(String userId, String deviceLabel) {
        String device = StringUtils.hasText(deviceLabel) ? "\"" + deviceLabel + "\"" : "A device";
        send(userId, "A security alert device was removed",
                device + " will no longer be warned about changes to this account. If that was not you, open "
                        + "the app now.");
    }

    /** The transition in the reader's own words, which is what makes an alert worth reacting to. */
    private static String sentence(String transition, String deviceLabel) {
        String device = StringUtils.hasText(deviceLabel) ? "\"" + deviceLabel + "\"" : "a device";
        return switch (transition == null ? "" : transition) {
            case "ADOPT_ROOT" -> device + " asked to become the device that controls this account.";
            case "DEVICE_GRANT" -> device + " was added as a device that can control this account.";
            case "DEVICE_REVOKE" -> device + " was asked to be removed from this account.";
            case "AUTHORITY_RECOVERY" -> "Someone asked to replace every device that controls this account, "
                    + "starting with " + device + ".";
            case "OPPOSE" -> "Someone objected to a pending change on this account.";
            default -> "A change to the devices that control this account was started by " + device + ".";
        };
    }

    private void send(String userId, String title, String body) {
        if (!StringUtils.hasText(userId)) {
            // Loud, because there is no such thing as a notification with nobody to send it to. Silence here
            // let three of the four notification kinds be dropped on every account for as long as they
            // existed, with nothing in any log to say so. AuthorityNotifications catches and logs this, so a
            // caller with no holder to name still cannot roll back a transition the chain accepted.
            throw new IllegalStateException("a security notification was raised with no account holder to send "
                    + "it to");
        }
        if (!isOutOfBand()) {
            // Nothing is configured. Silent rather than an error: the startup gate is what refuses a
            // deployment that turned the chain on with no channel at all.
            return;
        }
        Instant now = clock.instant();
        for (AuthorityNotificationRegistration row : registry.live(userId, now)) {
            transport(row).ifPresent(transport -> {
                AuthorityPushTransport.Outcome outcome =
                        transport.send(row.getToken(), row.getAppId(), title, body);
                registry.recordOutcome(row, outcome, now);
                if (outcome != AuthorityPushTransport.Outcome.DELIVERED) {
                    log.warn("A security notification for {} was not delivered ({}, {})", userId,
                            row.getTokenFingerprint(), outcome);
                }
            });
        }
    }

    private java.util.Optional<AuthorityPushTransport> transport(AuthorityNotificationRegistration row) {
        return transports.stream()
                .filter(candidate -> candidate.platform() == row.getPlatform())
                .filter(AuthorityPushTransport::isConfigured)
                .findFirst();
    }
}
