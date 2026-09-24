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

import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;

/**
 * A step-up an account holder performed in the web sheet, for one authority transition (ADM-009 decision 4
 * step 2).
 *
 * <p>It exists because the factor the policy asks for cannot always be produced where the transition is
 * started. The proof is a user-verifying passkey assertion, or the PIN where policy allows it, and one client
 * platform has no way to run the assertion natively. Without this row the policy would collapse to PIN-only
 * there, and an account that correctly chose passkey-only would be told to add a PIN to gain authority, which
 * is a worse account than the one it started with.
 *
 * <p>Four bindings, and each one closes a door:
 *
 * <ul>
 * <li><b>the account</b>, so a sheet run by one holder proves nothing about another;</li>
 * <li><b>the acting session</b>, by the hash of the access token that asked for the sheet, so a second
 * session of the same account cannot spend a proof it did not ask for;</li>
 * <li><b>the purpose</b>, because O9 asks for a possession proof of <em>this</em> transition, so a proof taken
 * for an adoption is not a proof for a recovery;</li>
 * <li><b>the clock</b>, at the challenge's own life, so a sheet left open in a background tab is not a
 * step-up an hour later.</li>
 * </ul>
 *
 * <p>{@link #factor} is written by the server from the ceremony it just ran and is only ever the passkey or
 * the PIN. There is no arm of the sheet that sends a code to the account's number, and no column here a
 * client could set to say which factor it produced.
 */
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "account_authority_web_step_up")
public class AuthorityWebStepUp {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false, columnDefinition = "TEXT")
    private String userId;

    @Column(name = "session_hash", nullable = false, length = 64)
    private String sessionHash;

    @Column(name = "purpose", nullable = false, length = 16)
    @Enumerated(EnumType.STRING)
    private Purpose purpose;

    @Column(name = "factor", nullable = false, length = 16)
    @Enumerated(EnumType.STRING)
    private AuthFactor factor;

    /**
     * When the credential presented came into being, which is what the fresh-factor hold weighs. Null when
     * the account's PIN has no recorded set time: the hold then has nothing to weigh, which is honest, where
     * a sentinel would be read as an age.
     */
    @Column(name = "factor_created_at")
    private Instant factorCreatedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public static AuthorityWebStepUp proved(String userId, String sessionHash, Purpose purpose, AuthFactor factor,
            Instant factorCreatedAt, Instant expiresAt, Instant now) {
        AuthorityWebStepUp stepUp = new AuthorityWebStepUp();
        stepUp.userId = userId;
        stepUp.sessionHash = sessionHash;
        stepUp.purpose = purpose;
        stepUp.factor = factor;
        stepUp.factorCreatedAt = factorCreatedAt;
        stepUp.expiresAt = expiresAt;
        stepUp.createdAt = now;
        return stepUp;
    }

    /** Unconsumed and unexpired: the only state the challenge endpoint may spend. */
    public boolean isSpendable(Instant now) {
        return consumedAt == null && now.isBefore(expiresAt);
    }
}
