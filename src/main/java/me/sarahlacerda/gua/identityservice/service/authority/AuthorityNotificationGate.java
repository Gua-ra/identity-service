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
 * Refuses to start a deployment that has the authority chain switched on without the things every window
 * in ADM-009 depends on. Gate 2 and the window floor, in one startup check.
 *
 * <p>Three refusals, and each one is a window that would otherwise be theatre:
 * <ol>
 * <li><b>No out-of-band notification channel</b> (gate 2). An adoption, a grant and a revocation all
 * complete unless the holder objects inside the window. With only the channels this service has today, a
 * SIM-swap attacker holds the phone and the recovery that preceded them emptied the sessions, so the window
 * is unwitnessed and the delay protects nobody.</li>
 * <li><b>A window under 24 hours</b> without the testing switch. The window is the whole security of the
 * transition (ADM-001 O9), and both durations are read from the environment, so one mistyped variable
 * would silently price an account takeover at a few minutes.</li>
 * <li><b>A challenge that outlives its step-up.</b> ADM-009 decision 4 step 2 asks for a step-up no older
 * than the challenge, which is 15 minutes. A longer TTL would make the step-up older than the record it
 * authorizes, which is the freshness defect the whole preimage rule exists to close.</li>
 * </ol>
 *
 * <p>Failing the start is the point. A misconfiguration that shows up only as an account taken over next
 * week is a misconfiguration nobody catches, and this is the pattern the recovery durations and the
 * placement signer already use.
 */
@Component
public class AuthorityNotificationGate {

    private static final Logger log = LoggerFactory.getLogger(AuthorityNotificationGate.class);

    /** The shortest opposition or recovery window a deployment may run without the testing switch. */
    static final Duration WINDOW_FLOOR = Duration.ofHours(24);

    /** The longest a challenge, and therefore the step-up that minted it, may stay spendable. */
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
            // Inert. Nothing here is read, so a half-configured deployment with the flag off starts and
            // behaves exactly as it did before the feature existed.
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
    /**
     * Refuses a transport whose signing key cannot be loaded, at startup rather than at the first alert.
     *
     * <p>"Configured" is what the gate above counts, and a credential that does not parse is configured by
     * that test and useless by every other one. Dev found this the hard way: a key stored as base64 of its
     * PEM file rather than of its DER left both transports counting as channels, the deployment started,
     * the first ADOPT_ROOT went pending, and the send failed with the window already running. An alert
     * nobody can receive is the failure gate 2 exists to prevent, so the key is loaded here, once, while
     * there is still someone watching a deployment.
     *
     * <p>Neither the key nor any part of it reaches the message.
     */
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
            // Said out loud, because "the variable is set" and "the credential parses" are different
            // facts and only the second one is a channel. A deployment that starts silently leaves an
            // operator reading environment variables to guess at the one that matters, and the gate
            // is the only place that knows. The property name, never its value.
            log.info("The account authority push credential at {} loaded as a {} key.", property, algorithm);
        } catch (RuntimeException ex) {
            throw new IllegalStateException(property + " does not load as a " + algorithm
                    + " key (" + ex.getMessage() + "). That transport has a base URL, so it counts as a "
                    + "channel for ADM-009 gate 2, and a channel that cannot sign announces nothing. "
                    + "Refusing to start.", ex);
        }
    }

}
