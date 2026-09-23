// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration;

/**
 * The security-notification registrations of one account (ADM-009 gate 2).
 *
 * <p>There is deliberately no bulk delete and no delete by user id. Every removal names one install and goes
 * through the three tiers of {@code AuthorityNotificationRegistry}, so a fresh post-recovery session cannot
 * empty the channel; a method here that took a user id would be exactly the shortcut that makes those tiers
 * decorative. Account deactivation is the one caller that removes every row, and it names them one by one
 * after the account itself is gone.
 */
public interface AuthorityNotificationRegistrationRepository
        extends JpaRepository<AuthorityNotificationRegistration, UUID> {

    List<AuthorityNotificationRegistration> findByUserId(String userId);

    Optional<AuthorityNotificationRegistration> findByUserIdAndInstallationId(String userId, String installationId);
}
