// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.repository;

import java.util.Optional;

import jakarta.persistence.LockModeType;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChainHead;

/**
 * The head row, and the lock every authority write takes on it (ADM-009 decision 3).
 *
 * <p>Deliberately absent: any method that writes a head without holding the lock. The compare-and-set on
 * {@code prevHash} and {@code seq} is only a compare-and-set because the row is read {@code FOR UPDATE}
 * first, so an unlocked read-then-save here would write one device's decision over another's.
 */
public interface AuthorityChainHeadRepository extends JpaRepository<AuthorityChainHead, String> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select h from AuthorityChainHead h where h.account = :account")
    Optional<AuthorityChainHead> findByAccountForUpdate(@Param("account") String account);

    Optional<AuthorityChainHead> findByAccount(String account);
}
