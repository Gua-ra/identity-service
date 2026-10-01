// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
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
 * Every removal needs a step-up on a factor past the fresh-factor hold, plus a device signature when the
 * row is bound to a device key.
 */
@Service
public class AuthorityNotificationRegistry {

    private static final Logger log = LoggerFactory.getLogger(AuthorityNotificationRegistry.class);

    private static final int MAX_LABEL_BYTES = AuthorityRecord.LABEL_LENGTH;

    private static final Pattern APNS_TOKEN = Pattern.compile("[0-9a-fA-F]+");
    private static final Pattern FCM_TOKEN = Pattern.compile("[\\x21-\\x7E]+");

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

    /**
     * Upsert on the installation id. Changing an existing row's push token needs a signature by an active
     * device, as a removal does.
     */
    @Transactional
    public Registered register(String userId, Registration request, String sessionHash, Instant now) {
        policy.requireEnabled();
        policy.requireNotificationsEnabled();
        String installationId = required(request.installationId(), "installation_id");
        Platform platform = platform(request.platform());
        String token = token(platform, request.token());
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
            if (!token.equals(row.getToken()) && deviceKey == null) {
                throw refused("authority_notification_destination_refused",
                        "Moving this install's alerts to another destination needs a signature from a device "
                                + "that holds this account's authority.");
            }
            row.setPlatform(platform);
            row.setAppId(appId);
            row.setToken(token);
            row.setTokenFingerprint(fingerprint(token));
            row.setDeviceLabel(label);
            if (deviceKey != null) {
                // The device key is only ever set from a verified signature.
                row.setAuthorityDeviceKeyB64(deviceKey);
            }
            row.setConsecutiveFailures(0);
            row.setLastSeenAt(now);
        }
        repository.save(row);
        log.info("A security-notification registration was stored for {} ({})", userId, row.getTokenFingerprint());
        return new Registered(row.getInstallationId(), row.getTokenFingerprint(),
                row.getAuthorityDeviceKeyB64() != null);
    }

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

    @Transactional
    public String remove(String userId, Removal request, String sessionHash, String requesterIp, Instant now) {
        policy.requireEnabled();
        policy.requireNotificationsEnabled();
        String target = required(request.installationId(), "installation_id");
        AuthorityNotificationRegistration row = repository.findByUserIdAndInstallationId(userId, target)
                .orElseThrow(() -> refused("authority_notification_unknown",
                        "There is no such registration on this account."));

        requireFactorAndSignature(userId, row, request, sessionHash, requesterIp, now);

        repository.delete(row);
        log.info("A security-notification registration was removed for {} ({})", userId,
                row.getTokenFingerprint());
        return row.getDeviceLabel();
    }

    private void requireFactorAndSignature(String userId, AuthorityNotificationRegistration row, Removal request,
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
        // The key on the row, never one the request names.
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
            throw refused("authority_notification_unknown_device",
                    "That device does not hold this account's authority.");
        }
    }

    @Transactional(readOnly = true)
    public List<AuthorityNotificationRegistration> listForHolder(String userId, Instant now) {
        policy.requireEnabled();
        policy.requireNotificationsEnabled();
        return live(userId, now);
    }

    @Transactional(readOnly = true)
    public List<AuthorityNotificationRegistration> live(String userId, Instant now) {
        return repository.findByUserId(userId).stream()
                .filter(row -> row.isLive(now, policy.registrationLife(), policy.registrationFailureLimit()))
                .toList();
    }

    /** Called after the transition has committed, so it needs its own transaction to be written at all. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
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

    /** An APNs token becomes part of the request path, so only the hex Apple issues is stored. */
    private static String token(Platform platform, String value) {
        String token = required(value, "token");
        Pattern shape = platform == Platform.APNS ? APNS_TOKEN : FCM_TOKEN;
        if (!shape.matcher(token).matches()) {
            throw refused("authority_notification_invalid", "token is not a push token of that platform.");
        }
        return token;
    }

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

    public record Registration(String installationId, String platform, String token, String appId,
            String deviceLabel, String authorityDeviceKeyB64, String challenge, String signature) {
    }

    public record Removal(String installationId, String passkeyStepUpId, JsonNode passkeyCredential, String pin,
            String challenge, String signature) {
    }

    public record Registered(String installationId, String tokenFingerprint, boolean bound) {
    }

}
