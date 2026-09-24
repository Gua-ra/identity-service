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

/**
 * Step-ups performed in the web sheet, looked up by the account, the acting session and the purpose together
 * (ADM-009 decision 4 step 2).
 *
 * <p>Deliberately absent: any finder by account alone, or by purpose alone. A step-up is proof that this
 * holder proved a factor for <em>this</em> transition from <em>this</em> session, and a lookup that dropped
 * one of those three would hand a caller a proof somebody else produced or produced for something else.
 */
public interface AuthorityWebStepUpRepository extends JpaRepository<AuthorityWebStepUp, UUID> {

    List<AuthorityWebStepUp> findByUserIdAndSessionHashAndPurposeAndConsumedAtIsNull(String userId,
            String sessionHash, Purpose purpose);

    /**
     * Swept on the write path rather than by a scheduler, exactly as the challenge and candidate tables are
     * swept and for the same reason: nothing in this application enables scheduling, and an expired step-up is
     * already refused when it is spent, so this only stops them piling up.
     */
    @Modifying
    @Query("delete from AuthorityWebStepUp s where s.expiresAt < :cutoff")
    int deleteExpired(@Param("cutoff") Instant cutoff);
}
