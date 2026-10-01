// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import me.sarahlacerda.gua.identityservice.domain.AuthorityHeadPublication;

/** No lock method: every writer already holds the chain head row FOR UPDATE. */
public interface AuthorityHeadPublicationRepository extends JpaRepository<AuthorityHeadPublication, String> {

    Optional<AuthorityHeadPublication> findByAccount(String account);
}
