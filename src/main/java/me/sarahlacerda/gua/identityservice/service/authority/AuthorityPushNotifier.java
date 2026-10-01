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

/** Counts as out of band only while a transport is configured. */
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
        // A notification may carry only the transition, the device label and the completion time.
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
            throw new IllegalStateException("a security notification was raised with no account holder to send "
                    + "it to");
        }
        if (!isOutOfBand()) {
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
