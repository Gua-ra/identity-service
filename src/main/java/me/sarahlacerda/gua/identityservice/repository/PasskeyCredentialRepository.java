package me.sarahlacerda.gua.identityservice.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import jakarta.persistence.LockModeType;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import me.sarahlacerda.gua.identityservice.domain.PasskeyCredential;

public interface PasskeyCredentialRepository extends JpaRepository<PasskeyCredential, UUID> {
    List<PasskeyCredential> findByAccountPrincipal(String accountPrincipal);

    boolean existsByAccountPrincipal(String accountPrincipal);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from PasskeyCredential c where c.accountPrincipal = :accountPrincipal")
    List<PasskeyCredential> findByAccountPrincipalForUpdate(@Param("accountPrincipal") String accountPrincipal);

    /** Cannot identify an account: all credentials of one account share a handle. */
    List<PasskeyCredential> findByUserHandle(String userHandle);

    Optional<PasskeyCredential> findByCredentialId(String credentialId);
}
