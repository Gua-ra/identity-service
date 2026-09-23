// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityProofs;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.domain.AuthorityDevice;
import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration;
import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration.Platform;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityNotificationRegistrationRepository;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityStepUpService.Accepted;

/**
 * The registrations that make ADM-009 gate 2 true, and the three tiers a removal has to pass.
 *
 * <h2>Why removal is asymmetric</h2>
 *
 * <p>The attacker this channel exists to defeat holds, after a completed account recovery: the phone number,
 * a PIN they chose seconds ago, a fresh session, and an account whose other sessions are ended. What they do
 * not hold is the previous owner's installation id, that install's authority device key, or any factor older
 * than the fresh-factor hold. The tiers are written against exactly that list:
 *
 * <ol>
 * <li><b>From the install itself.</b> The body names the caller's own installation id and no extra factor is
 * asked for, because the person holding that phone is the person the channel serves.</li>
 * <li><b>From another install of the same account.</b> A step-up on a factor that is itself past the
 * fresh-factor hold, so the PIN the recovery just minted is refused, plus, where the row carries a device
 * key, a signature by a key the chain has active and unquarantined, which the rank-0 account-recovery path
 * never mints.</li>
 * <li><b>From nowhere else.</b> No admin path, no bulk delete, and nothing reachable from a browser session,
 * because ADM-009 decision 6 forbids browser-held material authorizing anything.</li>
 * </ol>
 *
 * <p>Every accepted removal is announced to whatever registrations are left, so stripping the channel is loud
 * rather than silent. The announcement goes out after the row is gone rather than before, so the install that
 * was just removed is not among the ones told, which is the whole point of telling anybody.
 *
 * <p>The honest bound, stated rather than hidden: an attacker with the owner's unlocked phone removes that
 * install's own registration, which is the same power ADM-009 decision 5 already concedes to a borrowed
 * unlocked phone. And on an account with exactly one install, the only registration belongs to the install
 * performing the transition, so notifying it notifies whoever holds that phone. Gate 2 is satisfied in form
 * and not in substance for that account, which is why the README says so.
 */
@Service
public class AuthorityNotificationRegistry {

    private static final Logger log = LoggerFactory.getLogger(AuthorityNotificationRegistry.class);

    /** The 16 label bytes a record may carry, which is all a notification is allowed to name. */
    private static final int MAX_LABEL_BYTES = AuthorityRecord.LABEL_LENGTH;

    private final AuthorityNotificationRegistrationRepository repository;
    private final AuthorityDeviceRepository deviceRepository;
    private final AuthorityAccounts accounts;
    private final AuthorityChallengeService challenges;
    private final AuthorityStepUpService stepUps;
    private final AuthorityPolicy policy;

    public AuthorityNotificationRegistry(AuthorityNotificationRegistrationRepository repository,
            AuthorityDeviceRepository deviceRepository, AuthorityAccounts accounts,
            AuthorityChallengeService challenges, AuthorityStepUpService stepUps, AuthorityPolicy policy) {
        this.repository = repository;
        this.deviceRepository = deviceRepository;
        this.accounts = accounts;
        this.challenges = challenges;
        this.stepUps = stepUps;
        this.policy = policy;
    }

    // --- Registration ---------------------------------------------------------

    /**
     * Creates or refreshes one install's registration, as an upsert on the installation id.
     *
     * <p>An upsert rather than an insert because the id is stable across sign-out and re-login: without it
     * every re-login would add a row and stale tokens would accumulate forever, and a sweep would be the only
     * thing standing between the account and a list of destinations that no longer exist.
     */
    @Transactional
    public Registered register(String userId, Registration request, String sessionHash, Instant now) {
        policy.requireEnabled();
        policy.requireNotificationsEnabled();
        String installationId = required(request.installationId(), "installation_id");
        Platform platform = platform(request.platform());
        String token = required(request.token(), "token");
        String appId = required(request.appId(), "app_id");
        String label = label(request.deviceLabel());
        String deviceKey = bind(userId, installationId, request, sessionHash, now);

        AuthorityNotificationRegistration row = repository
                .findByUserIdAndInstallationId(userId, installationId)
                .orElse(null);
        if (row == null) {
            row = AuthorityNotificationRegistration.registered(userId, installationId, platform, appId, token,
                    fingerprint(token), label, deviceKey, now);
        } else {
            row.setPlatform(platform);
            row.setAppId(appId);
            row.setToken(token);
            row.setTokenFingerprint(fingerprint(token));
            row.setDeviceLabel(label);
            if (deviceKey != null) {
                // Only ever set by a signature, so a refresh cannot quietly drop the binding that makes this
                // row hard to remove, and cannot quietly add one either.
                row.setAuthorityDeviceKeyB64(deviceKey);
            }
            // A refreshed token is a working destination again, whatever the transport said about the old one.
            row.setConsecutiveFailures(0);
            row.setLastSeenAt(now);
        }
        repository.save(row);
        log.info("A security-notification registration was stored for {} ({})", userId, row.getTokenFingerprint());
        return new Registered(row.getInstallationId(), row.getTokenFingerprint(),
                row.getAuthorityDeviceKeyB64() != null);
    }

    /**
     * The device key the install proved it holds, or null when it presented none.
     *
     * <p>Proved, not claimed. The field is what makes tier 2 removal need a signature the account-recovery
     * path cannot produce, so a row that could simply assert a key would let an attacker plant a registration
     * the owner's own device can never remove.
     */
    private String bind(String userId, String installationId, Registration request, String sessionHash,
            Instant now) {
        if (!StringUtils.hasText(request.authorityDeviceKeyB64())) {
            return null;
        }
        byte[] deviceKey = decode(request.authorityDeviceKeyB64(), "authority_device_key");
        if (deviceKey.length != AuthorityRecord.KEY_LENGTH) {
            throw refused("authority_notification_invalid_key", "That device key is not the right length.");
        }
        AuthorityAccounts.Resolved account = accounts.require(userId);
        requireActiveDevice(account, request.authorityDeviceKeyB64(), now);

        byte[] challenge = challenges
                .spend(account.reference(), sessionHash, Purpose.NOTIFY, request.challenge(), now).challenge();
        byte[] signature = decode(required(request.signature(), "signature"), "signature");
        if (!AuthorityProofs.verifyNotificationBinding(deviceKey, account.bytes(),
                sha256(installationId), challenge, signature)) {
            throw refused("authority_notification_invalid_signature",
                    "That device did not sign this registration.");
        }
        return request.authorityDeviceKeyB64();
    }

    // --- Removal --------------------------------------------------------------

    /**
     * Removes one registration, through whichever tier the caller can pass.
     *
     * @param callerInstallationId the installation id the calling app holds, which is what makes tier 1
     *                             reachable. Null when the caller did not name its own install
     */
    @Transactional
    public String remove(String userId, Removal request, String callerInstallationId, String sessionHash,
            String requesterIp, Instant now) {
        policy.requireEnabled();
        policy.requireNotificationsEnabled();
        String target = required(request.installationId(), "installation_id");
        AuthorityNotificationRegistration row = repository.findByUserIdAndInstallationId(userId, target)
                .orElseThrow(() -> refused("authority_notification_unknown",
                        "There is no such registration on this account."));

        boolean fromTheInstallItself = target.equals(callerInstallationId);
        if (!fromTheInstallItself) {
            requireSecondTier(userId, row, request, sessionHash, requesterIp, now);
        }

        repository.delete(row);
        log.info("A security-notification registration was removed for {} ({}, own install: {})", userId,
                row.getTokenFingerprint(), fromTheInstallItself);
        // The caller announces this to whatever is left, which is why the label comes back rather than nothing.
        // The row is already gone, so the install that was removed is not among the ones told.
        return row.getDeviceLabel();
    }

    /**
     * Tier 2: a step-up on a factor past the fresh-factor hold, and a device signature where the row carries a
     * key.
     *
     * <p>The hold is what refuses the attacker. Their only factor is the PIN the recovery minted seconds ago,
     * and ADM-009 decision 9 rule 3 refuses a credential inside the hold; the account-level half of the same
     * rule refuses them again while the recovery itself is inside it.
     */
    private void requireSecondTier(String userId, AuthorityNotificationRegistration row, Removal request,
            String sessionHash, String requesterIp, Instant now) {
        Accepted accepted = stepUps.accept(userId, policy.notificationRemovalStepUp(),
                "AUTHORITY_NOTIFICATION_REMOVE", request.passkeyStepUpId(), request.passkeyCredential(),
                request.pin(), requesterIp);
        policy.enforceFreshFactorHold(accepted.factorCreatedAt());
        policy.enforceRecoveryOutsideHold(userId);

        if (row.getAuthorityDeviceKeyB64() == null) {
            return;
        }
        AuthorityAccounts.Resolved account = accounts.require(userId);
        byte[] deviceKey = decode(row.getAuthorityDeviceKeyB64(), "authority_device_key");
        // The key on the row, not one the request names: the request cannot choose which key it has to be.
        requireActiveDevice(account, row.getAuthorityDeviceKeyB64(), now);
        byte[] challenge = challenges
                .spend(account.reference(), sessionHash, Purpose.NOTIFY, request.challenge(), now).challenge();
        byte[] signature = decode(required(request.signature(), "signature"), "signature");
        if (!AuthorityProofs.verifyNotificationBinding(deviceKey, account.bytes(),
                sha256(row.getInstallationId()), challenge, signature)) {
            throw refused("authority_notification_invalid_signature",
                    "Removing that registration needs a signature from the device it names.");
        }
    }

    private void requireActiveDevice(AuthorityAccounts.Resolved account, String deviceKeyB64, Instant now) {
        AuthorityDevice device = deviceRepository
                .findByAccountAndDeviceKeyB64(account.reference(), deviceKeyB64)
                .orElseThrow(() -> refused("authority_notification_unknown_device",
                        "That device does not hold this account's authority."));
        if (!device.isUnquarantinedActive(now)) {
            // A quarantined device may not sign an authority-sensitive approval, and this is one.
            throw refused("authority_notification_unknown_device",
                    "That device does not hold this account's authority.");
        }
    }

    // --- Reading and liveness -------------------------------------------------

    /**
     * Every registration of the account, for its own holder to look at.
     *
     * <p>Flag-gated, unlike {@link #live}, because this one answers a request rather than serving a
     * notification: with the channel off there is nothing to list and no reason to say so in detail.
     */
    @Transactional(readOnly = true)
    public List<AuthorityNotificationRegistration> listForHolder(String userId, Instant now) {
        policy.requireEnabled();
        policy.requireNotificationsEnabled();
        return live(userId, now);
    }

    /** Every registration of the account that still counts as a channel. */
    @Transactional(readOnly = true)
    public List<AuthorityNotificationRegistration> live(String userId, Instant now) {
        return repository.findByUserId(userId).stream()
                .filter(row -> row.isLive(now, policy.registrationLife(), policy.registrationFailureLimit()))
                .toList();
    }

    /**
     * Records what a transport learned, and retires a destination it says is gone.
     *
     * <p>Its own transaction, because it runs after a transition has already been accepted: a dead push token
     * must not roll back a record the chain has taken.
     */
    @Transactional
    public void recordOutcome(AuthorityNotificationRegistration row, AuthorityPushTransport.Outcome outcome,
            Instant now) {
        AuthorityNotificationRegistration stored = repository.findById(row.getId()).orElse(null);
        if (stored == null) {
            return;
        }
        switch (outcome) {
            case DELIVERED -> {
                stored.setConsecutiveFailures(0);
                stored.setLastSeenAt(now);
            }
            case RETRYABLE, UNREGISTERED -> {
                stored.setConsecutiveFailures(stored.getConsecutiveFailures()
                        + (outcome == AuthorityPushTransport.Outcome.UNREGISTERED
                                ? policy.registrationFailureLimit()
                                : 1));
                stored.setLastFailureAt(now);
            }
        }
        repository.save(stored);
    }

    // --- Small helpers --------------------------------------------------------

    private static String required(String value, String field) {
        if (!StringUtils.hasText(value)) {
            throw refused("authority_notification_invalid", field + " is required.");
        }
        return value.trim();
    }

    private static Platform platform(String value) {
        try {
            return Platform.valueOf(required(value, "platform").toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw refused("authority_notification_invalid", "platform must be APNS or FCM.");
        }
    }

    /**
     * The label, refused when it is longer than the 16 bytes a record may carry.
     *
     * <p>Refused rather than truncated: the notification names the label the record named, and a label the
     * server shortened would not be the one the account holder is being asked to recognise.
     */
    private static String label(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.getBytes(StandardCharsets.UTF_8).length > MAX_LABEL_BYTES) {
            throw refused("authority_notification_invalid",
                    "device_label is at most " + MAX_LABEL_BYTES + " bytes of UTF-8.");
        }
        return trimmed;
    }

    /** SHA-256 hex of the token, so a log or a support conversation can name a row without printing it. */
    static String fingerprint(String token) {
        return HexFormat.of().formatHex(sha256(token));
    }

    static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable in this JVM", ex);
        }
    }

    private static byte[] decode(String value, String field) {
        try {
            return Base64.getUrlDecoder().decode(value.trim());
        } catch (IllegalArgumentException ex) {
            throw refused("authority_notification_invalid", field + " is not base64url.");
        }
    }

    private static AuthorityTransitionException refused(String code, String message) {
        return new AuthorityTransitionException(HttpStatus.BAD_REQUEST, code, message);
    }

    /**
     * What an install registers.
     *
     * @param installationId       client-generated, held in the keychain or keystore, stable across sign-out
     * @param platform             APNS or FCM
     * @param token                the push destination
     * @param appId                the same app id the Matrix pusher already sends
     * @param deviceLabel          at most the 16 bytes a record may carry
     * @param authorityDeviceKeyB64 optional, and only accepted with a signature over a spent challenge
     */
    public record Registration(String installationId, String platform, String token, String appId,
            String deviceLabel, String authorityDeviceKeyB64, String challenge, String signature) {
    }

    /** What a removal presents. Which tier it reaches is decided by what it can produce, never by a flag. */
    public record Removal(String installationId, String passkeyStepUpId, JsonNode passkeyCredential, String pin,
            String challenge, String signature) {
    }

    /**
     * What the account holder is told about their own registration. Never the token.
     *
     * @param bound whether the row carries a device key, which is what makes its removal need a signature
     */
    public record Registered(String installationId, String tokenFingerprint, boolean bound) {
    }

}
