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
 * One device authority key the chain has activated (ADM-009 decision 5).
 *
 * <p>Per device, never one key copied to every device. Copying makes revocation meaningless, because the
 * revoked device still holds the key the account is defined by, and it turns any single device compromise
 * into a permanent account compromise with no way back short of recovery.
 */
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "account_authority_device")
public class AuthorityDevice {

    public enum State {
        /** Counts as authority, may sign. */
        ACTIVE,
        /**
         * Granted, inside its own opposition window. May not sign a grant, a revocation or an approval,
         * and does not count toward the active device a revocation must leave behind.
         */
        QUARANTINED,
        /** Removed by a revocation, by a recovery, or by an opposition to its own grant. */
        REVOKED
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "account_id", nullable = false, length = 64)
    private String account;

    @Column(name = "device_key_b64", nullable = false, columnDefinition = "TEXT")
    private String deviceKeyB64;

    @Column(name = "label", columnDefinition = "TEXT")
    private String label;

    @Column(name = "flags", nullable = false)
    private short flags;

    @Column(name = "granted_seq", nullable = false)
    private long grantedSeq;

    @Column(name = "revoked_seq")
    private Long revokedSeq;

    @Column(name = "quarantine_until")
    private Instant quarantineUntil;

    @Column(name = "state", nullable = false, length = 16)
    @Enumerated(EnumType.STRING)
    private State state;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public static AuthorityDevice granted(String account, String deviceKeyB64, String label, long grantedSeq,
            Instant quarantineUntil, State state, Instant now) {
        AuthorityDevice device = new AuthorityDevice();
        device.account = account;
        device.deviceKeyB64 = deviceKeyB64;
        device.label = label;
        device.flags = 0;
        device.grantedSeq = grantedSeq;
        device.quarantineUntil = quarantineUntil;
        device.state = state;
        device.createdAt = now;
        return device;
    }

    /** Whether the quarantine of decision 5 is still running at {@code now}. */
    public boolean isQuarantined(Instant now) {
        return state == State.QUARANTINED && quarantineUntil != null && now.isBefore(quarantineUntil);
    }

    /** Active and past its quarantine: the only thing that counts as this account's authority. */
    public boolean isUnquarantinedActive(Instant now) {
        if (state == State.REVOKED) {
            return false;
        }
        return !isQuarantined(now);
    }
}
