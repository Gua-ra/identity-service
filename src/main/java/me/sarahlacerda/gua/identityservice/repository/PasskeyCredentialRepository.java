package me.sarahlacerda.gua.identityservice.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import me.sarahlacerda.gua.identityservice.domain.PasskeyCredential;

public interface PasskeyCredentialRepository extends JpaRepository<PasskeyCredential, UUID> {
    /** @deprecated Ownership is keyed on the account principal. */
    @Deprecated
    List<PasskeyCredential> findByUserId(String userId);

    List<PasskeyCredential> findByAccountPrincipal(String accountPrincipal);

    boolean existsByAccountPrincipal(String accountPrincipal);

    /** Cannot identify an account: all credentials of one account share a handle. */
    List<PasskeyCredential> findByUserHandle(String userHandle);

    Optional<PasskeyCredential> findByCredentialId(String credentialId);

    boolean existsByUserId(String userId);
}
