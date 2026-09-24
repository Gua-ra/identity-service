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
 * <p>{@code headHash} and {@code headSeq} name the last record <em>placed</em> in a slot, whatever became of
 * it. That is the slot reservation of decision 3: a record inside an opposition window has already taken its
 * {@code seq}, and a cancelled one keeps it. Without that, every delayed transition loses to an immediate one
 * and an attacker holding any active device starves every revocation aimed at them, one cheap record per
 * window. It also means the hash chain has no gaps and no branch: the next record always follows the last
 * one placed, and whether a record took effect is its own {@code state} rather than a hole in the chain.
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
    }
}
