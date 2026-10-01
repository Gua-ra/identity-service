// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.domain.AuthorityWebStepUp;

/** Lookups must use the account, the session and the purpose together. */
public interface AuthorityWebStepUpRepository extends JpaRepository<AuthorityWebStepUp, UUID> {

    List<AuthorityWebStepUp> findByUserIdAndSessionHashAndPurposeAndConsumedAtIsNull(String userId,
            String sessionHash, Purpose purpose);

    @Modifying
    @Query("delete from AuthorityWebStepUp s where s.expiresAt < :cutoff")
    int deleteExpired(@Param("cutoff") Instant cutoff);
}
