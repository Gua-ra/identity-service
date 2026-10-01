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
 * One row per account, locked FOR UPDATE by every writer. The head includes a record still inside its
 * opposition window.
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

    @Column(name = "pending_extended", nullable = false)
    private boolean pendingExtended;

    /** Kept here because a retry replaces the cancelled row, so counting rows would undercount. */
    @Column(name = "cancelled_count", nullable = false)
    private int cancelledCount;

    @Column(name = "cooldown_until")
    private Instant cooldownUntil;

    /** The cooldown blocks only records of this type. */
    @Column(name = "cooldown_magic", length = 4)
    private String cooldownMagic;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

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

    public long nextSeq() {
        return headSeq + 1;
    }

    public String nextPrevHash() {
        return headHash;
    }

    public boolean isChainEmpty() {
        return headSeq == 0;
    }

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

    public void rollBackTo(String recordHash, long seq) {
        headHash = recordHash;
        headSeq = seq;
        cancelledCount++;
    }

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
