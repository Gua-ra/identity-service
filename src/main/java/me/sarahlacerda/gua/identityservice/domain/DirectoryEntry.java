package me.sarahlacerda.gua.identityservice.domain;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
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
@Table(name = "directory_entries")
public class DirectoryEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "phone_digest", nullable = false, unique = true, length = 64)
    private String phoneDigest;

    /**
     * Display-only masked phone (e.g. "••••4567"). Not reversible to the full
     * number; the raw phone is never stored.
     */
    @Column(name = "phone_masked", length = 32)
    private String phoneMasked;

    @Column(name = "user_id", nullable = false)
    private String userId;

    /**
     * Stable identifier of the homeserver this account lives on (see
     * {@code Homeserver#id()}). Nullable for rows created before routing existed.
     */
    @Column(name = "homeserver_id", length = 64)
    private String homeserverId;

    /**
     * Globally-unique (within the Gua federation) human-readable handle, decoupled
     * from the Matrix user id. Acts as the routing alias for discovery/mentions.
     */
    @Column(name = "username", length = 64)
    private String username;

    @Column(name = "display_name")
    private String displayName;

    /**
     * Contact-discovery opt-out. When {@code false} the account is excluded from
     * address-book matching ({@code /directory/lookup}); messaging is unaffected.
     */
    @Column(name = "discoverable", nullable = false)
    private boolean discoverable = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Builder
    public DirectoryEntry(String phoneDigest, String phoneMasked, String userId, String homeserverId,
            String username, String displayName) {
        this.phoneDigest = phoneDigest;
        this.phoneMasked = phoneMasked;
        this.userId = userId;
        this.homeserverId = homeserverId;
        this.username = username;
        this.displayName = displayName;
    }

    @PrePersist
    void prePersist() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = Instant.now();
    }
}
