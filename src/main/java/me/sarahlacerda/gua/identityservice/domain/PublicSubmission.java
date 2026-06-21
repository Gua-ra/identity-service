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

/**
 * A submission from one of the public gua.global web forms (a support request or
 * a beta-access sign-up). Persisted as the durable record before an out-of-band
 * GitHub issue is opened for the operator to act on.
 */
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "public_submissions")
public class PublicSubmission {

    public enum Type {
        SUPPORT,
        BETA;

        public String dbValue() {
            return name().toLowerCase();
        }
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "type", nullable = false)
    private String type;

    @Column(name = "name")
    private String name;

    @Column(name = "email", nullable = false)
    private String email;

    @Column(name = "platform")
    private String platform;

    @Column(name = "message")
    private String message;

    /** HMAC digest of the source IP (never the raw IP). */
    @Column(name = "source_ip_hash")
    private String sourceIpHash;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Builder
    public PublicSubmission(Type type, String name, String email, String platform, String message,
            String sourceIpHash) {
        this.type = type != null ? type.dbValue() : null;
        this.name = name;
        this.email = email;
        this.platform = platform;
        this.message = message;
        this.sourceIpHash = sourceIpHash;
    }

    @PrePersist
    void prePersist() {
        this.createdAt = Instant.now();
    }
}
