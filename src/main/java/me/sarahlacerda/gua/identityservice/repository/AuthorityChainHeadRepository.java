// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.repository;

import java.util.Optional;

import jakarta.persistence.LockModeType;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChainHead;

/** Every write must first read the row FOR UPDATE. Do not add an unlocked read-then-save. */
public interface AuthorityChainHeadRepository extends JpaRepository<AuthorityChainHead, String> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select h from AuthorityChainHead h where h.account = :account")
    Optional<AuthorityChainHead> findByAccountForUpdate(@Param("account") String account);

    Optional<AuthorityChainHead> findByAccount(String account);
}
