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

public interface AccountGenesisRepository extends JpaRepository<AccountGenesisRecord, String> {

    Optional<AccountGenesisRecord> findByUserId(String userId);

    boolean existsByUserId(String userId);

    Optional<AccountGenesisRecord> findByAttachHandleHash(String attachHandleHash);

    long countByOrigin(Origin origin);

    @Query("select r.userId from AccountGenesisRecord r where r.userId in :userIds")
    List<String> findExistingUserIds(@Param("userIds") Collection<String> userIds);

    /** Atomic compare-and-set: returns 0 when the row is no longer PENDING with this handle hash. */
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

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from AccountGenesisRecord r where r.state = :pending and r.expiresAt < :cutoff")
    int deleteExpiredPending(@Param("pending") State pending, @Param("cutoff") Instant cutoff);
}
