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
 * <p>Deliberately absent: any delete. A record leaves {@code PENDING} by having its {@code state} settled,
 * and the bytes of a record in the chain stay exactly as they were received, because the record hash and
 * every later {@code prevHash} cover them.
 *
 * <p>One position is written twice, and only one: a <em>cancelled</em> record gives its slot back
 * ({@code AuthorityChainHead}), so the next record built for that position replaces it. That is what lets an
 * account whose first adoption was opposed adopt again, at the {@code seq} both clients build a retry with.
 * The count of cancellations that decision 4's bounds weigh therefore lives on the head, which a replacement
 * does not touch.
 */
public interface AuthorityChainRecordRepository extends JpaRepository<AuthorityChainRecord, AuthorityChainRecord.Key> {

    List<AuthorityChainRecord> findByAccountOrderBySeqAsc(String account);

    Optional<AuthorityChainRecord> findByAccountAndSeq(String account, long seq);

    Optional<AuthorityChainRecord> findByAccountAndRecordHash(String account, String recordHash);

    List<AuthorityChainRecord> findByAccountAndState(String account, State state);
}
