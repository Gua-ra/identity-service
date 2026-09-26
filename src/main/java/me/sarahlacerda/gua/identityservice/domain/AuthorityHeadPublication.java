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
 * What this deployment has published about one account's settled chain head (ADM-009 decision 12).
 *
 * <p>One row per account. The history of heads is in the transparency log, which is append-only; this row
 * is only a record of what was last sent, and it exists for two reasons.
 *
 * <p><b>It is what makes a republish idempotent.</b> The bytes are kept verbatim, so a delivery that has to
 * be retried, or a second pass over the same head, resends exactly the bytes that were signed the first
 * time. The leaf commits the SHA-256 of those bytes, so a repeat commits the same payload rather than a
 * second leaf saying the same thing with a different {@code issuedAt}. Signing again on every pass would
 * have made the log grow once per read of an account's own state, and the log's size is the roster version
 * (ADM-001 L6), so that growth moves where new accounts are placed.
 *
 * <p><b>It is what stops the published head going backwards.</b> The chain head row's {@code headHash} names
 * the last record placed and not yet cancelled, including one still inside its opposition window, and a
 * cancellation rolls it back to that record's own {@code prevHash}. Only a settled head is ever published,
 * and a publication is replaced only when the settled head moves strictly forward, so a rollback leaves the
 * published position where it was rather than trying to unsay a leaf that cannot be unsaid.
 *
 * <p>The account is held as {@code account} rather than under the name of the identifier it carries, like
 * every other row in this feature. See {@code AuthorityAccounts} and {@code AccountIdNotReadGuardTest}.
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

    /** The canonical bytes as signed, base64url unpadded. Never re-encoded. */
    @Column(name = "record_b64", nullable = false, columnDefinition = "TEXT")
    private String recordB64;

    /** Detached, never part of the signed bytes. */
    @Column(name = "signature_b64", nullable = false, columnDefinition = "TEXT")
    private String signatureB64;

    /** SHA-256 hex over the canonical bytes: exactly what the ACCOUNT_AUTHORITY leaf commits. */
    @Column(name = "payload_hash", nullable = false, length = 64)
    private String payloadHash;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    @Column(name = "not_after", nullable = false)
    private Instant notAfter;

    @Column(name = "signed_at", nullable = false)
    private Instant signedAt;

    /** When the resolver accepted it; null while it is signed but unacknowledged. */
    @Column(name = "confirmed_at")
    private Instant confirmedAt;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    /**
     * When the last delivery attempt was made, or null when none has been.
     *
     * <p>The only thing that bounds retries. The catch-up rides the same lazy path the account holder's own
     * reads take, so without a floor a resolver that has been unreachable for an hour would put a socket
     * timeout in front of every one of those reads.
     */
    @Column(name = "last_attempt_at")
    private Instant lastAttemptAt;

    /** A freshly signed head, not yet delivered. */
    public static AuthorityHeadPublication of(String account, long headSeq, String headHash, String homeserverId,
            String recordB64, String signatureB64, String payloadHash, Instant issuedAt, Instant notAfter,
            Instant now) {
        AuthorityHeadPublication publication = new AuthorityHeadPublication();
        publication.account = account;
        publication.replaceWith(headSeq, headHash, homeserverId, recordB64, signatureB64, payloadHash, issuedAt,
                notAfter, now);
        return publication;
    }

    /** Replaces the published head with a newly signed one, which resets the delivery state. */
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
        // A freshly signed head is delivered at once; the floor only ever holds back a retry.
        this.lastAttemptAt = null;
    }

    /** True when this row is unconfirmed and its retry floor has not passed yet. */
    public boolean isRetryTooSoon(Instant now, java.time.Duration retryAfter) {
        return lastAttemptAt != null && lastAttemptAt.plus(retryAfter).isAfter(now);
    }

    /** True when this row already published exactly that head. */
    public boolean publishes(long seq, String hash) {
        return headSeq == seq && headHash != null && headHash.equalsIgnoreCase(hash);
    }

    public boolean isConfirmed() {
        return confirmedAt != null;
    }
}
