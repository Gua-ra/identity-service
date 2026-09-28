package me.sarahlacerda.gua.identityservice.domain;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "passkey_credentials")
public class PasskeyCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * The account's Matrix user id at the moment this credential was registered.
     *
     * <p>Audit only. It is deliberately NOT the ownership key any more and must never be read to decide who
     * a credential belongs to, because an account's Matrix identity can change and this column cannot: a
     * placement change would make it stale and every ownership question answered through it wrong. Use
     * {@link #accountPrincipal}.
     */
    @Column(name = "user_id", nullable = false)
    private String userId;

    /**
     * The stable Gua account principal that owns this credential: the canonical accountId spelling.
     *
     * <p>This is the ownership key. It is also what the WebAuthn user handle carries, as its 34 canonical
     * bytes, so the authenticator itself replays the owner on every assertion. Null only on a row written
     * before the stable model, which the application refuses rather than resolving.
     */
    @Column(name = "account_principal", length = 64)
    private String accountPrincipal;

    @Column(name = "user_handle", nullable = false)
    private String userHandle;

    @Column(name = "credential_id", nullable = false, unique = true)
    private String credentialId;

    @Column(name = "public_key_cose", nullable = false, columnDefinition = "TEXT")
    private String publicKeyCose;

    @Column(name = "signature_count", nullable = false)
    private long signatureCount;

    @Column(name = "backup_eligible", nullable = false)
    private boolean backupEligible;

    @Column(name = "backup_state", nullable = false)
    private boolean backupState;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Builder
    public PasskeyCredential(
            String accountPrincipal,
            String userId,
            String userHandle,
            String credentialId,
            String publicKeyCose,
            long signatureCount,
            boolean backupEligible,
            boolean backupState) {
        this.accountPrincipal = accountPrincipal;
        this.userId = userId;
        this.userHandle = userHandle;
        this.credentialId = credentialId;
        this.publicKeyCose = publicKeyCose;
        this.signatureCount = signatureCount;
        this.backupEligible = backupEligible;
        this.backupState = backupState;
    }

    @PrePersist
    void prePersist() {
        this.createdAt = Instant.now();
    }
}
