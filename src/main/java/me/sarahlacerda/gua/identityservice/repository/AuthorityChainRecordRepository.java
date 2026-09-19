// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChainRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChainRecord.State;

/**
 * The append-only chain.
 *
 * <p>Deliberately absent: any delete, and any update of the bytes, the hash or the position. A record
 * leaves {@code PENDING} by having its {@code state} settled and nothing else; the bytes stay exactly as
 * they were received, because the record hash and every later {@code prevHash} cover them.
 */
public interface AuthorityChainRecordRepository extends JpaRepository<AuthorityChainRecord, AuthorityChainRecord.Key> {

    List<AuthorityChainRecord> findByAccountOrderBySeqAsc(String account);

    Optional<AuthorityChainRecord> findByAccountAndSeq(String account, long seq);

    Optional<AuthorityChainRecord> findByAccountAndRecordHash(String account, String recordHash);

    List<AuthorityChainRecord> findByAccountAndState(String account, State state);
}
