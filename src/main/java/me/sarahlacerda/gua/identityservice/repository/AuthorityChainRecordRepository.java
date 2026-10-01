// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChainRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChainRecord.State;

/** Append-only: no deletes. A cancelled record's position may be overwritten by its retry. */
public interface AuthorityChainRecordRepository extends JpaRepository<AuthorityChainRecord, AuthorityChainRecord.Key> {

    List<AuthorityChainRecord> findByAccountOrderBySeqAsc(String account);

    Optional<AuthorityChainRecord> findByAccountAndSeq(String account, long seq);

    Optional<AuthorityChainRecord> findByAccountAndRecordHash(String account, String recordHash);

    List<AuthorityChainRecord> findByAccountAndState(String account, State state);

    Optional<AuthorityChainRecord> findFirstByAccountAndStateAndSeqLessThanOrderBySeqDesc(String account,
            State state, long seq);
}
