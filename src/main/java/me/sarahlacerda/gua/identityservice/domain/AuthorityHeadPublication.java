// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * The last head published for an account. The signed bytes are kept so a retry resends them unchanged,
 * and the published head only moves forward.
 */
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "account_authority_publication")
public class AuthorityHeadPublication {

    @Id
    @Column(name = "account_id", nullable = false, length = 64)
    private String account;

    @Column(name = "head_seq", nullable = false)
    private long headSeq;

    @Column(name = "head_hash", nullable = false, length = 64)
    private String headHash;

    @Column(name = "homeserver_id", nullable = false, length = 64)
    private String homeserverId;

    @Column(name = "record_b64", nullable = false, columnDefinition = "TEXT")
    private String recordB64;

    @Column(name = "signature_b64", nullable = false, columnDefinition = "TEXT")
    private String signatureB64;

    @Column(name = "payload_hash", nullable = false, length = 64)
    private String payloadHash;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    @Column(name = "not_after", nullable = false)
    private Instant notAfter;

    @Column(name = "signed_at", nullable = false)
    private Instant signedAt;

    @Column(name = "confirmed_at")
    private Instant confirmedAt;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "last_attempt_at")
    private Instant lastAttemptAt;

    public static AuthorityHeadPublication of(String account, long headSeq, String headHash, String homeserverId,
            String recordB64, String signatureB64, String payloadHash, Instant issuedAt, Instant notAfter,
            Instant now) {
        AuthorityHeadPublication publication = new AuthorityHeadPublication();
        publication.account = account;
        publication.replaceWith(headSeq, headHash, homeserverId, recordB64, signatureB64, payloadHash, issuedAt,
                notAfter, now);
        return publication;
    }

    public void replaceWith(long headSeq, String headHash, String homeserverId, String recordB64,
            String signatureB64, String payloadHash, Instant issuedAt, Instant notAfter, Instant now) {
        this.headSeq = headSeq;
        this.headHash = headHash;
        this.homeserverId = homeserverId;
        this.recordB64 = recordB64;
        this.signatureB64 = signatureB64;
        this.payloadHash = payloadHash;
        this.issuedAt = issuedAt;
        this.notAfter = notAfter;
        this.signedAt = now;
        this.confirmedAt = null;
        this.attempts = 0;
        this.lastAttemptAt = null;
    }

    public boolean isRetryTooSoon(Instant now, java.time.Duration retryAfter) {
        return lastAttemptAt != null && lastAttemptAt.plus(retryAfter).isAfter(now);
    }

    public boolean publishes(long seq, String hash) {
        return headSeq == seq && headHash != null && headHash.equalsIgnoreCase(hash);
    }

    public boolean isConfirmed() {
        return confirmedAt != null;
    }
}
