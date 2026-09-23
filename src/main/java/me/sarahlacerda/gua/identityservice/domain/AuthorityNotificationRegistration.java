// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.domain;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * One install of the account holder's app that can be warned about a pending authority transition
 * (ADM-009 gate 2).
 *
 * <p>Keyed on an installation id the client keeps in its keychain or keystore, not on a session and not on
 * a Matrix device id. That is the whole property: a Matrix pusher lives under a session, and completing an
 * account recovery ends every session of the user in the same transaction that mints the attacker's PIN, so
 * a channel that dies with the sessions is empty at exactly the moment a window needs it.
 *
 * <p>Nothing in the recovery path can reach this row. {@code AccountRecoveryService.complete} writes
 * {@code identity_users} and {@code passkey_credentials}, and the session sign-out runs in another service
 * against another database. The survival is therefore a structural fact rather than a policy somebody could
 * be talked out of, and it is what {@code AuthorityNotificationSurvivesRecoveryTest} asserts.
 */
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "security_notification_device")
public class AuthorityNotificationRegistration {

    /** Which transport addresses this install. */
    public enum Platform {
        APNS, FCM
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false, columnDefinition = "TEXT")
    private String userId;

    @Column(name = "installation_id", nullable = false, columnDefinition = "TEXT")
    private String installationId;

    @Column(name = "platform", nullable = false, columnDefinition = "TEXT")
    @Enumerated(EnumType.STRING)
    private Platform platform;

    @Column(name = "app_id", nullable = false, columnDefinition = "TEXT")
    private String appId;

    @Column(name = "token", nullable = false, columnDefinition = "TEXT")
    private String token;

    @Column(name = "token_fingerprint", nullable = false, columnDefinition = "TEXT")
    private String tokenFingerprint;

    @Column(name = "device_label", columnDefinition = "TEXT")
    private String deviceLabel;

    @Column(name = "authority_device_key_b64", columnDefinition = "TEXT")
    private String authorityDeviceKeyB64;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    @Column(name = "consecutive_failures", nullable = false)
    private int consecutiveFailures;

    @Column(name = "last_failure_at")
    private Instant lastFailureAt;

    public static AuthorityNotificationRegistration registered(String userId, String installationId,
            Platform platform, String appId, String token, String tokenFingerprint, String deviceLabel,
            String authorityDeviceKeyB64, Instant now) {
        AuthorityNotificationRegistration registration = new AuthorityNotificationRegistration();
        registration.userId = userId;
        registration.installationId = installationId;
        registration.platform = platform;
        registration.appId = appId;
        registration.token = token;
        registration.tokenFingerprint = tokenFingerprint;
        registration.deviceLabel = deviceLabel;
        registration.authorityDeviceKeyB64 = authorityDeviceKeyB64;
        registration.createdAt = now;
        registration.lastSeenAt = now;
        return registration;
    }

    /**
     * Whether this install still counts as a channel.
     *
     * <p>A registration the transport has repeatedly reported unregistered, or one nothing has been heard
     * from for longer than the configured life, is not a channel. Gate 2 is a claim that the holder will be
     * told, so a destination that provably cannot be reached must not keep the claim alive.
     */
    public boolean isLive(Instant now, java.time.Duration life, int failureLimit) {
        return consecutiveFailures < failureLimit && lastSeenAt.plus(life).isAfter(now);
    }
}
