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

import me.sarahlacerda.gua.identityservice.domain.AuthorityDeviceCandidate;

/** Keys new devices have offered, waiting for a grant (ADM-009 decision 5, revision 4). */
public interface AuthorityDeviceCandidateRepository extends JpaRepository<AuthorityDeviceCandidate, UUID> {

    List<AuthorityDeviceCandidate> findByAccount(String account);

    Optional<AuthorityDeviceCandidate> findByAccountAndDeviceKeyB64(String account, String deviceKeyB64);

    /**
     * Swept on the write path rather than by a scheduler, exactly as the challenge table is swept and for the
     * same reason: nothing in this application enables scheduling, and an expired candidate is already refused
     * when a grant names it, so this only stops them piling up.
     */
    @Modifying
    @Query("delete from AuthorityDeviceCandidate c where c.expiresAt < :now")
    void deleteExpired(@Param("now") Instant now);
}
