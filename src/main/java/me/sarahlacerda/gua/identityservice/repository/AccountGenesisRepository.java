package me.sarahlacerda.gua.identityservice.repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord.Origin;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord.State;

/**
 * Genesis rows, keyed by accountId.
 *
 * <p>Deliberately absent: any method that updates {@link Origin}. A bootstrap account is not adopted
 * into a rooted one in this phase, and {@code AccountGenesisOriginImmutableTest} fails the build if such
 * a method appears.
 */
public interface AccountGenesisRepository extends JpaRepository<AccountGenesisRecord, String> {

    Optional<AccountGenesisRecord> findByUserId(String userId);

    boolean existsByUserId(String userId);

    /**
     * Looks a pending registration up by the hash of the attach handle. The handle arrives on the login
     * session, never in the body of the request that attaches.
     */
    Optional<AccountGenesisRecord> findByAttachHandleHash(String attachHandleHash);

    long countByOrigin(Origin origin);

    /** Of the given accounts, the ones that already hold a genesis row. Used to keep backfill batches idempotent. */
    @Query("select r.userId from AccountGenesisRecord r where r.userId in :userIds")
    List<String> findExistingUserIds(@Param("userIds") Collection<String> userIds);

    /**
     * Attaches a pending registration to an account, as one atomic compare-and-set.
     *
     * <p>This is what makes two sessions racing on one handle resolve to a single attach: the update
     * matches only a row that is still PENDING and still carries this handle hash, so the second writer
     * updates zero rows and its signup fails rather than silently attaching an already-attached genesis.
     * The unique index on {@code user_id} is the second line of the same defence.
     *
     * @return rows updated: 1 on success, 0 when the row is gone, expired past its window, already
     *         attached, or was attached by someone else in between
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            update AccountGenesisRecord r
               set r.userId = :userId,
                   r.state = :attached,
                   r.attachedAt = :attachedAt,
                   r.attachHandleHash = null,
                   r.expiresAt = null
             where r.accountId = :accountId
               and r.state = :pending
               and r.attachHandleHash = :attachHandleHash
            """)
    int attach(@Param("accountId") String accountId,
            @Param("attachHandleHash") String attachHandleHash,
            @Param("userId") String userId,
            @Param("attachedAt") Instant attachedAt,
            @Param("pending") State pending,
            @Param("attached") State attached);

    /**
     * Expiry sweep: pending registrations nobody attached inside their window.
     *
     * <p>Clears the persistence context, so a caller that already loaded one of these rows does not go
     * on reading a deleted one out of the first-level cache.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from AccountGenesisRecord r where r.state = :pending and r.expiresAt < :cutoff")
    int deleteExpiredPending(@Param("pending") State pending, @Param("cutoff") Instant cutoff);
}
