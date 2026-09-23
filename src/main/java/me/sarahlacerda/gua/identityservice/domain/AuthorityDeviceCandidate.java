// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.domain;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A key a new device has offered, waiting for an existing device to grant it (ADM-009 decision 5, revision 4).
 *
 * <p>The public half only. The new device generates its own key and never receives another device's, so what
 * crosses between the two phones is 32 public bytes and an eight-character fingerprint a human compares. A
 * holder of this row can sign nothing with it.
 *
 * <p>It expires quickly on purpose. A candidate is a step in a ceremony two people are performing right now,
 * and one left lying around is a key over which a grant could later be signed without anybody comparing
 * anything.
 */
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "account_authority_candidate")
public class AuthorityDeviceCandidate {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "account_id", nullable = false, length = 64)
    private String account;

    @Column(name = "device_key_b64", nullable = false, columnDefinition = "TEXT")
    private String deviceKeyB64;

    @Column(name = "fingerprint", nullable = false, length = 16)
    private String fingerprint;

    @Column(name = "label", columnDefinition = "TEXT")
    private String label;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    public static AuthorityDeviceCandidate offered(String account, String deviceKeyB64, String fingerprint,
            String label, Instant now, Instant expiresAt) {
        AuthorityDeviceCandidate candidate = new AuthorityDeviceCandidate();
        candidate.account = account;
        candidate.deviceKeyB64 = deviceKeyB64;
        candidate.fingerprint = fingerprint;
        candidate.label = label;
        candidate.createdAt = now;
        candidate.expiresAt = expiresAt;
        return candidate;
    }

    public boolean isLive(Instant now) {
        return now.isBefore(expiresAt);
    }
}
