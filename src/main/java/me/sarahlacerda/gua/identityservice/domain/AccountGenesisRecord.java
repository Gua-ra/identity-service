package me.sarahlacerda.gua.identityservice.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Local to identity-service and never replicated. The accountId is permanent and origin is never updated. */
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "account_genesis")
public class AccountGenesisRecord {

    public enum Origin {
        GENESIS,
        BOOTSTRAP
    }

    public enum State {
        PENDING,
        ATTACHED
    }

    @Id
    @Column(name = "account_id", nullable = false, length = 64)
    private String accountId;

    /** Null while PENDING. */
    @Column(name = "user_id", unique = true)
    private String userId;

    @Enumerated(EnumType.STRING)
    @Column(name = "origin", nullable = false, length = 16)
    private Origin origin;

    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false, length = 16)
    private State state;

    @Column(name = "genesis_version", nullable = false)
    private short genesisVersion;

    @Column(name = "genesis_suite", nullable = false)
    private short genesisSuite;

    @Column(name = "genesis_b64", nullable = false)
    private String genesisB64;

    /** Null for BOOTSTRAP. */
    @Column(name = "authority_key_b64")
    private String authorityKeyB64;

    /** SHA-256 hex of the single-use attach handle. The handle itself is never stored. */
    @Setter
    @Column(name = "attach_handle_hash", length = 64)
    private String attachHandleHash;

    @Setter
    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "attached_at")
    private Instant attachedAt;

    private AccountGenesisRecord(String accountId, String userId, Origin origin, State state, short genesisVersion,
            short genesisSuite, String genesisB64, String authorityKeyB64, String attachHandleHash,
            Instant expiresAt, Instant attachedAt) {
        this.accountId = accountId;
        this.userId = userId;
        this.origin = origin;
        this.state = state;
        this.genesisVersion = genesisVersion;
        this.genesisSuite = genesisSuite;
        this.genesisB64 = genesisB64;
        this.authorityKeyB64 = authorityKeyB64;
        this.attachHandleHash = attachHandleHash;
        this.expiresAt = expiresAt;
        this.attachedAt = attachedAt;
    }

    public static AccountGenesisRecord pendingGenesis(String accountId, short version, short suite, String genesisB64,
            String authorityKeyB64, String attachHandleHash, Instant expiresAt) {
        return new AccountGenesisRecord(accountId, null, Origin.GENESIS, State.PENDING, version, suite, genesisB64,
                authorityKeyB64, attachHandleHash, expiresAt, null);
    }

    public static AccountGenesisRecord attachedGenesis(String accountId, String userId, short version, short suite,
            String genesisB64, String authorityKeyB64, Instant attachedAt) {
        return new AccountGenesisRecord(accountId, userId, Origin.GENESIS, State.ATTACHED, version, suite,
                genesisB64, authorityKeyB64, null, null, attachedAt);
    }

    public static AccountGenesisRecord attachedBootstrap(String accountId, String userId, short version, short suite,
            String genesisB64, Instant attachedAt) {
        return new AccountGenesisRecord(accountId, userId, Origin.BOOTSTRAP, State.ATTACHED, version, suite,
                genesisB64, null, null, null, attachedAt);
    }

    @PrePersist
    void prePersist() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    public boolean isAttached() {
        return state == State.ATTACHED;
    }
}
