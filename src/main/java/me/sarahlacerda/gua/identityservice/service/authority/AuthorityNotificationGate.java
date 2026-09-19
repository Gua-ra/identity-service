// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;

import jakarta.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.AuthorityProperties;

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
}
