// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;

import jakarta.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.AuthorityProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.NotificationProperties;

/**
 * Refuses to start with the chain enabled but no out-of-band notification channel, a window under 24
 * hours, or a challenge TTL over 15 minutes.
 */
@Component
public class AuthorityNotificationGate {

    private static final Logger log = LoggerFactory.getLogger(AuthorityNotificationGate.class);

    static final Duration WINDOW_FLOOR = Duration.ofHours(24);

    static final Duration MAX_CHALLENGE_TTL = Duration.ofMinutes(15);

    private final IdentityServiceProperties properties;
    private final AuthorityNotifications notifications;

    public AuthorityNotificationGate(IdentityServiceProperties properties, AuthorityNotifications notifications) {
        this.properties = properties;
        this.notifications = notifications;
    }

    @PostConstruct
    public void verify() {
        validate(properties.getAuthority(), notifications.hasOutOfBandChannel());
    }

    static void validate(AuthorityProperties authority, boolean outOfBandNotifications) {
        if (!authority.isEnabled()) {
            return;
        }
        if (!outOfBandNotifications) {
            throw new IllegalStateException("identity.authority.enabled is true but no out-of-band "
                    + "notification channel is wired. ADM-009 gate 2: a pending authority transition must "
                    + "be announced on a channel that is neither the account's phone number nor a session "
                    + "an account recovery revokes, and a log line is not a channel. Refusing to start.");
        }
        requireLoadableKeys(authority);
        if (authority.getChallengeTtl().compareTo(MAX_CHALLENGE_TTL) > 0) {
            throw new IllegalStateException("identity.authority.challenge-ttl (" + authority.getChallengeTtl()
                    + ") must be at most " + MAX_CHALLENGE_TTL + ". ADM-009 decision 4 step 2 wants a step-up "
                    + "no older than the challenge it authorizes. Refusing to start.");
        }
        boolean tooShort = authority.getOppositionWindow().compareTo(WINDOW_FLOOR) < 0
                || authority.getRecoveryWindow().compareTo(WINDOW_FLOOR) < 0;
        if (!tooShort) {
            return;
        }
        if (authority.isAllowShortWindowsForTesting()) {
            log.warn("The account authority windows are shortened (opposition={}, recovery={}). "
                    + "identity.authority.allow-short-windows-for-testing is on; this must never be set "
                    + "outside a dev deployment.", authority.getOppositionWindow(), authority.getRecoveryWindow());
            return;
        }
        throw new IllegalStateException("identity.authority.opposition-window ("
                + authority.getOppositionWindow() + ") and identity.authority.recovery-window ("
                + authority.getRecoveryWindow() + ") must each be at least " + WINDOW_FLOOR
                + ". The window is the whole security of the transition (ADM-001 O9). Refusing to start. "
                + "Shorter windows are for dev only and need "
                + "identity.authority.allow-short-windows-for-testing=true.");
    }
    private static void requireLoadableKeys(AuthorityProperties authority) {
        NotificationProperties notifications = authority.getNotifications();
        if (StringUtils.hasText(notifications.getApns().getBaseUrl())) {
            require("EC", notifications.getApns().getPrivateKeyPkcs8Base64(),
                    "identity.authority.notifications.apns.private-key-pkcs8-base64");
        }
        if (StringUtils.hasText(notifications.getFcm().getBaseUrl())) {
            require("RSA", notifications.getFcm().getPrivateKeyPkcs8Base64(),
                    "identity.authority.notifications.fcm.private-key-pkcs8-base64");
        }
    }

    private static void require(String algorithm, String configured, String property) {
        try {
            AuthorityPushKeys.load(algorithm, configured);
            log.info("The account authority push credential at {} loaded as a {} key.", property, algorithm);
        } catch (RuntimeException ex) {
            throw new IllegalStateException(property + " does not load as a " + algorithm
                    + " key (" + ex.getMessage() + "). That transport has a base URL, so it counts as a "
                    + "channel for ADM-009 gate 2, and a channel that cannot sign announces nothing. "
                    + "Refusing to start.", ex);
        }
    }

}
