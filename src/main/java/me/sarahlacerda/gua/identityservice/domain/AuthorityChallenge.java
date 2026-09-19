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

import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;

/**
 * A server challenge minted for one transition (ADM-009 decision 2, "one preimage rule, for every type").
 *
 * <p>Only the SHA-256 of the challenge is stored, the way {@code account_genesis} stores only the hash of an
 * attach handle: a dump of this table hands nobody a challenge to sign. The row is held against the account
 * and the acting stepped-up session together, is single use, and is burned on acceptance <em>and</em> on
 * refusal, so a captured request body is useless.
 *
 * <p>{@code factor} and {@code factorCreatedAt} record which step-up minted it and when that credential came
 * into being, so the fresh-factor hold is weighed on the credential actually presented rather than on
 * whatever the account happens to hold now.
 */
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "account_authority_challenge")
public class AuthorityChallenge {

    /** What the challenge may be spent on. A step-up for one purpose does not carry over to another. */
    public enum Purpose {
        ADOPT, GRANT, REVOKE, RECOVER, APPROVE
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "account_id", nullable = false, length = 64)
    private String account;

    @Column(name = "session_hash", nullable = false, length = 64)
    private String sessionHash;

    @Column(name = "purpose", nullable = false, length = 16)
    @Enumerated(EnumType.STRING)
    private Purpose purpose;

    @Column(name = "challenge_hash", nullable = false, length = 64, unique = true)
    private String challengeHash;

    @Column(name = "factor", nullable = false, length = 16)
    @Enumerated(EnumType.STRING)
    private AuthFactor factor;

    @Column(name = "factor_created_at")
    private Instant factorCreatedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "spent_at")
    private Instant spentAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public static AuthorityChallenge minted(String account, String sessionHash, Purpose purpose,
            String challengeHash, AuthFactor factor, Instant factorCreatedAt, Instant expiresAt, Instant now) {
        AuthorityChallenge challenge = new AuthorityChallenge();
        challenge.account = account;
        challenge.sessionHash = sessionHash;
        challenge.purpose = purpose;
        challenge.challengeHash = challengeHash;
        challenge.factor = factor;
        challenge.factorCreatedAt = factorCreatedAt;
        challenge.expiresAt = expiresAt;
        challenge.createdAt = now;
        return challenge;
    }

    public boolean isSpendable(Instant now) {
        return spentAt == null && now.isBefore(expiresAt);
    }
}
