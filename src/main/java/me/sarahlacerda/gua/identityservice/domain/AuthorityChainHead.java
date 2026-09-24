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

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecord;

/**
 * The single head of an account's authority chain (ADM-009 decision 3).
 *
 * <p>Exactly one row per account, locked {@code FOR UPDATE} by every writer. Acceptance is a
 * compare-and-set against {@code headHash} and {@code headSeq}, so two devices acting at once produce one
 * winner and one refusal carrying the current head. There is no merge, no last-writer-wins, and no state in
 * which two chains exist.
 *
 * <p>{@code headHash} and {@code headSeq} name the last record <em>placed</em> in a slot and not yet
 * cancelled. That is the slot reservation of decision 3: a record inside an opposition window has already
 * taken its {@code seq}, so every delayed transition is not simply outrun by an immediate one and an attacker
 * holding any active device cannot starve a revocation aimed at them with one cheap record per window.
 *
 * <p>A <em>cancelled</em> record gives its slot back, and that is not a detail. While it kept the slot, one
 * free opposition to a first adoption left {@code headSeq} at 1 forever, and {@code AdoptRoot} is permitted
 * only on an empty chain: the account could never adopt again and reported {@code AUTHORITY_LOST} without
 * ever having been rooted. So a cancellation rolls the head back to the cancelled record's own
 * {@code prevHash} and {@code seq - 1}, which for a first record is the empty head, exactly the position both
 * clients build a retry against.
 *
 * <p>{@link #getCancelledCount()} is therefore kept here rather than counted from the rows: a retry lands at
 * the position the cancelled record held, so the row itself does not survive a retry, and decision 4's bound
 * on free oppositions has to be counted somewhere that does.
 *
 * <p>The pending fields say that the last placed record is still inside its window, and carry its rank so a
 * rank comparison does not have to re-decode it.
 */
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "account_authority_head")
public class AuthorityChainHead {

    @Id
    @Column(name = "account_id", nullable = false, length = 64)
    private String account;

    @Column(name = "head_hash", nullable = false, length = 64)
    private String headHash;

    @Column(name = "head_seq", nullable = false)
    private long headSeq;

    @Column(name = "pending_seq")
    private Long pendingSeq;

    @Column(name = "pending_hash", length = 64)
    private String pendingHash;

    @Column(name = "pending_magic", length = 4)
    private String pendingMagic;

    @Column(name = "pending_rank")
    private Short pendingRank;

    @Column(name = "pending_effective_at")
    private Instant pendingEffectiveAt;

    /**
     * Whether the pending record's window has already been extended once (ADM-009 decision 7).
     *
     * <p>Counted, because "extends the window once" is the whole of what an active device may do to a recovery
     * signed by the committed recovery authority key. Uncounted, the same objection was re-submittable
     * indefinitely: nothing an extension changes is part of the staleness check, an Oppose asks for no factor,
     * and no backoff is charged for one, so a thief holding every device could postpone the owner's recovery
     * forever, which is the outcome L13.3's refusal to make the active key the veto exists to prevent.
     */
    @Column(name = "pending_extended", nullable = false)
    private boolean pendingExtended;

    /**
     * How many records this account has had cancelled, which decision 4's bounds count to decide whether an
     * opposition has to present a factor.
     *
     * <p>Counted here rather than from the {@code CANCELLED} rows, because a cancelled record gives its slot
     * back and a retry at that position replaces the row. Counted from the rows, one opposition would be free,
     * then the next retry would make the following one free again, and the bound that stops a stolen bearer
     * session vetoing an account out of ever holding authority would never bind.
     */
    @Column(name = "cancelled_count", nullable = false)
    private int cancelledCount;

    @Column(name = "cooldown_until")
    private Instant cooldownUntil;

    /**
     * The magic of the record the cooldown was written for, so the cooldown refuses another transition of
     * <em>that</em> shape and nothing else.
     *
     * <p>Without it one column refused every shape at once, which is the absolute freeze decision 3 rejected:
     * an intruder cycling a revocation the owner objects to would freeze the owner's grant, revocation,
     * self-revocation and recovery for a full window each time, while paying only their own doubling backoff.
     */
    @Column(name = "cooldown_magic", length = 4)
    private String cooldownMagic;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /** A fresh head for an account whose chain is empty. */
    public static AuthorityChainHead empty(String account, Instant now) {
        AuthorityChainHead head = new AuthorityChainHead();
        head.account = account;
        head.headHash = AuthorityRecord.emptyHeadHash();
        head.headSeq = 0L;
        head.updatedAt = now;
        return head;
    }

    public boolean hasPending() {
        return pendingSeq != null;
    }

    /** The seq the next record must carry. */
    public long nextSeq() {
        return headSeq + 1;
    }

    /** The hash the next record's prevHash must equal. */
    public String nextPrevHash() {
        return headHash;
    }

    /** No record has been placed yet. */
    public boolean isChainEmpty() {
        return headSeq == 0;
    }

    /** Places a record in the next slot, pending or not. */
    public void place(String recordHash, long seq, String magic, short rank, Instant effectiveAt, Instant now) {
        headHash = recordHash;
        headSeq = seq;
        updatedAt = now;
        if (effectiveAt == null) {
            clearPending();
            return;
        }
        pendingSeq = seq;
        pendingHash = recordHash;
        pendingMagic = magic;
        pendingRank = rank;
        pendingEffectiveAt = effectiveAt;
        pendingExtended = false;
    }

    /**
     * Gives a cancelled record's slot back, so the position it held is the next position again.
     *
     * <p>The empty-chain head hash is a first record's all-zero {@code prevHash}, so rolling back the first
     * record of a chain leaves exactly the head an adoption is built against.
     */
    public void rollBackTo(String prevHash, long seq) {
        headHash = prevHash;
        headSeq = seq - 1;
        cancelledCount++;
    }

    /** Opens the cooldown one cancelled record's shape owes, per ADM-009 decision 4's bounds. */
    public void startCooldown(String magic, Instant until) {
        cooldownMagic = magic;
        cooldownUntil = until;
    }

    public void clearPending() {
        pendingSeq = null;
        pendingHash = null;
        pendingMagic = null;
        pendingRank = null;
        pendingEffectiveAt = null;
        pendingExtended = false;
    }
}
