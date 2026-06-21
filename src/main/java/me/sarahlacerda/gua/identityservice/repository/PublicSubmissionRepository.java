package me.sarahlacerda.gua.identityservice.repository;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import me.sarahlacerda.gua.identityservice.domain.PublicSubmission;

public interface PublicSubmissionRepository extends JpaRepository<PublicSubmission, UUID> {
}
