// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import jakarta.persistence.LockModeType;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;

/** Lookups must start from the challenge hash, never from the account or the purpose alone. */
public interface AuthorityChallengeRepository extends JpaRepository<AuthorityChallenge, UUID> {

    Optional<AuthorityChallenge> findByChallengeHash(String challengeHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from AuthorityChallenge c where c.challengeHash = :challengeHash")
    Optional<AuthorityChallenge> findByChallengeHashForUpdate(@Param("challengeHash") String challengeHash);

    List<AuthorityChallenge> findByAccountAndPurposeAndSpentAtIsNull(String account, Purpose purpose);

    @Modifying
    @Query("delete from AuthorityChallenge c where c.expiresAt < :cutoff")
    int deleteExpired(@Param("cutoff") Instant cutoff);
}
