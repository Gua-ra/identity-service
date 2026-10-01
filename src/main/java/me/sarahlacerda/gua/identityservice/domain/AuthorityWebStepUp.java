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
 * A step-up proved in the web sheet, bound to the account, the requesting access token, one purpose
 * and an expiry.
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

    /** Null when the PIN has no recorded set time. */
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

    public boolean isSpendable(Instant now) {
        return consumedAt == null && now.isBefore(expiresAt);
    }
}
