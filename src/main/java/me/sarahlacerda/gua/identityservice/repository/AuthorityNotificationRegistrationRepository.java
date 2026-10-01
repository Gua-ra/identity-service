// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration;

/** No bulk delete and no delete by user id: every removal names one install and passes the registry's checks. */
public interface AuthorityNotificationRegistrationRepository
        extends JpaRepository<AuthorityNotificationRegistration, UUID> {

    List<AuthorityNotificationRegistration> findByUserId(String userId);

    Optional<AuthorityNotificationRegistration> findByUserIdAndInstallationId(String userId, String installationId);
}
