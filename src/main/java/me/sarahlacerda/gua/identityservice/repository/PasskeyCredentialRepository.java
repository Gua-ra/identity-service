package me.sarahlacerda.gua.identityservice.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import me.sarahlacerda.gua.identityservice.domain.PasskeyCredential;

public interface PasskeyCredentialRepository extends JpaRepository<PasskeyCredential, UUID> {
    /**
     * @deprecated ownership is keyed on the stable account principal. This remains only for the retirement
     *             of pre-stable rows, which are identified by having no principal at all.
     */
    @Deprecated
    List<PasskeyCredential> findByUserId(String userId);

    /** Every credential the stable account principal owns. The ownership query. */
    List<PasskeyCredential> findByAccountPrincipal(String accountPrincipal);

    /** Whether the stable account principal owns any credential. */
    boolean existsByAccountPrincipal(String accountPrincipal);

    /**
     * Kept with no production caller on purpose: a regression test asserts the assertion path never calls it.
     * Identifying a user from a handle is a decode, and several credentials of one account share a handle, so
     * no query on this column can answer it.
     */
    List<PasskeyCredential> findByUserHandle(String userHandle);

    Optional<PasskeyCredential> findByCredentialId(String credentialId);

    boolean existsByUserId(String userId);
}
