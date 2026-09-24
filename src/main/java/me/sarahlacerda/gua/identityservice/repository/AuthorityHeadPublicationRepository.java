// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import me.sarahlacerda.gua.identityservice.domain.AuthorityHeadPublication;

/**
 * What has been published about each account's settled chain head (ADM-009 decision 12).
 *
 * <p>No lock method, because every write goes through a caller that already holds the head row
 * {@code FOR UPDATE}: the publication is decided from the same locked head it describes, so two writers
 * cannot decide two different heads for one account. Reads outside that lock exist only to confirm a
 * delivery, which is idempotent on its own.
 */
public interface AuthorityHeadPublicationRepository extends JpaRepository<AuthorityHeadPublication, String> {

    Optional<AuthorityHeadPublication> findByAccount(String account);
}
