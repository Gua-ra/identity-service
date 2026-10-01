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
 * Keyed on an installation id rather than a session, so the row survives the session revocation an
 * account recovery performs.
 */
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "security_notification_device")
public class AuthorityNotificationRegistration {

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

    public boolean isLive(Instant now, java.time.Duration life, int failureLimit) {
        return consecutiveFailures < failureLimit && lastSeenAt.plus(life).isAfter(now);
    }
}
