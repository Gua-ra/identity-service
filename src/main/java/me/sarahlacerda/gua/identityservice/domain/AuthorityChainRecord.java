// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.domain;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@IdClass(AuthorityChainRecord.Key.class)
@Table(name = "account_authority_record")
public class AuthorityChainRecord {

    public enum State {
        PENDING,
        ACTIVE,
        CANCELLED,
        EXPIRED
    }

    @Id
    @Column(name = "account_id", nullable = false, length = 64)
    private String account;

    @Id
    @Column(name = "seq", nullable = false)
    private long seq;

    @Column(name = "magic", nullable = false, length = 4)
    private String magic;

    @Column(name = "record_b64", nullable = false, columnDefinition = "TEXT")
    private String recordB64;

    @Column(name = "record_hash", nullable = false, length = 64)
    private String recordHash;

    @Column(name = "prev_hash", nullable = false, length = 64)
    private String prevHash;

    @Column(name = "signature_b64", nullable = false, columnDefinition = "TEXT")
    private String signatureB64;

    @Column(name = "authorizing_key_b64", nullable = false, columnDefinition = "TEXT")
    private String authorizingKeyB64;

    @Column(name = "state", nullable = false, length = 16)
    @jakarta.persistence.Enumerated(jakarta.persistence.EnumType.STRING)
    private State state;

    @Column(name = "effective_at")
    private Instant effectiveAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "settled_at")
    private Instant settledAt;

    public static AuthorityChainRecord of(String account, long seq, String magic, String recordB64,
            String recordHash, String prevHash, String signatureB64, String authorizingKeyB64, State state,
            Instant effectiveAt, Instant now) {
        AuthorityChainRecord row = new AuthorityChainRecord();
        row.account = account;
        row.seq = seq;
        row.magic = magic;
        row.recordB64 = recordB64;
        row.recordHash = recordHash;
        row.prevHash = prevHash;
        row.signatureB64 = signatureB64;
        row.authorizingKeyB64 = authorizingKeyB64;
        row.state = state;
        row.effectiveAt = effectiveAt;
        row.createdAt = now;
        row.settledAt = state == State.PENDING ? null : now;
        return row;
    }

    public static class Key implements Serializable {

        private String account;
        private long seq;

        public Key() {
        }

        public Key(String account, long seq) {
            this.account = account;
            this.seq = seq;
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Key key && seq == key.seq && Objects.equals(account, key.account);
        }

        @Override
        public int hashCode() {
            return Objects.hash(account, seq);
        }
    }
}
