// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import me.sarahlacerda.gua.identityservice.domain.AuthorityDevice;

/** The device set the chain leaves active (ADM-009 decision 5). */
public interface AuthorityDeviceRepository extends JpaRepository<AuthorityDevice, UUID> {

    List<AuthorityDevice> findByAccount(String account);

    Optional<AuthorityDevice> findByAccountAndDeviceKeyB64(String account, String deviceKeyB64);
}
