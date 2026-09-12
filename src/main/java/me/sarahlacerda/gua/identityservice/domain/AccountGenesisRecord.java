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

/**
 * One account's genesis row: the object its accountId is derived from, and the account it is attached to
 * (ADM-008 decision 2, ADM-001 L3 and L5).
 *
 * <p>The row is local to identity-service and is not replicated: the MXID to accountId link stays
 * private here. Nothing in Phase 3 reads it for routing or for login.
 *
 * <p>An accountId is permanent. Deactivating an account leaves this row in place (L3), and no code path
 * updates {@link #origin}: a bootstrap account is not adopted into a rooted one in this phase.
 */
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "account_genesis")
public class AccountGenesisRecord {

    /** Where the account's identity is rooted. The audit marker ADM-001 L5 requires. */
    public enum Origin {
        /** Rooted in an {@code AccountGenesis} the client registered and proved possession of. */
        GENESIS,
        /** Bootstrap path B1: no committed authority key, root class byte 0x00 inside the id. */
        BOOTSTRAP
    }

    public enum State {
        /** Registered, not yet attached to an account. Carries an attach handle and an expiry. */
        PENDING,
        /** Attached to the account named by {@link #userId}. */
        ATTACHED
    }

    @Id
    @Column(name = "account_id", nullable = false, length = 64)
    private String accountId;

    /** The MXID once attached; null while PENDING. Unique, so one account holds one genesis. */
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

    /** The exact canonical bytes as received, base64url. The accountId is the hash of these. */
    @Column(name = "genesis_b64", nullable = false)
    private String genesisB64;

    /** Raw 32-byte Ed25519 authority key, base64url. Null for BOOTSTRAP, which commits no key. */
    @Column(name = "authority_key_b64")
    private String authorityKeyB64;

    /**
     * SHA-256 hex of the single-use attach handle; the handle itself is never stored.
     *
     * <p>Settable, with {@link #expiresAt}: re-registering the same genesis while it is still pending
     * rotates both. Every other field is fixed at construction, and {@link #origin} above all: it is the
     * audit marker ADM-001 L5 rests on, so it has no mutator at all and no query updates it.
     */
    @Setter
    @Column(name = "attach_handle_hash", length = 64)
    private String attachHandleHash;

    /** When a pending registration stops being attachable. Rotated with the handle. */
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

    /** A registered but unattached {@code AccountGenesis}. */
    public static AccountGenesisRecord pendingGenesis(String accountId, short version, short suite, String genesisB64,
            String authorityKeyB64, String attachHandleHash, Instant expiresAt) {
        return new AccountGenesisRecord(accountId, null, Origin.GENESIS, State.PENDING, version, suite, genesisB64,
                authorityKeyB64, attachHandleHash, expiresAt, null);
    }

    /**
     * A genesis row after its attach: the shape {@code AccountGenesisRepository.attach} leaves behind,
     * with the handle and the window burned and the account named.
     */
    public static AccountGenesisRecord attachedGenesis(String accountId, String userId, short version, short suite,
            String genesisB64, String authorityKeyB64, Instant attachedAt) {
        return new AccountGenesisRecord(accountId, userId, Origin.GENESIS, State.ATTACHED, version, suite,
                genesisB64, authorityKeyB64, null, null, attachedAt);
    }

    /** A bootstrap accountId, attached to its account the moment it is minted. */
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
