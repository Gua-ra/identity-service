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
