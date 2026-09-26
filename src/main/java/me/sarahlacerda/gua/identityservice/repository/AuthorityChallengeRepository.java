// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;

/**
 * Server challenges, looked up only by the hash of the bytes the caller returned.
 *
 * <p>Deliberately absent: any finder that returns a challenge by account or by purpose alone. A challenge
 * is proof that the holder was handed those exact bytes; a lookup that did not start from them would let a
 * caller spend a challenge it never received.
 */
public interface AuthorityChallengeRepository extends JpaRepository<AuthorityChallenge, UUID> {

    Optional<AuthorityChallenge> findByChallengeHash(String challengeHash);

    List<AuthorityChallenge> findByAccountAndPurposeAndSpentAtIsNull(String account, Purpose purpose);

    @Modifying
    @Query("delete from AuthorityChallenge c where c.expiresAt < :cutoff")
    int deleteExpired(@Param("cutoff") Instant cutoff);
}
