package me.sarahlacerda.gua.identityservice.service.account;

import java.util.Map;
import java.util.Set;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import me.sarahlacerda.gua.identityservice.repository.DirectoryEntryRepository;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.repository.PasskeyCredentialRepository;
import me.sarahlacerda.gua.identityservice.repository.TrustedDeviceRepository;
import me.sarahlacerda.gua.identityservice.service.security.AccountReauthService;
import me.sarahlacerda.gua.identityservice.service.security.EndOtherSessionsService;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyPrincipals;
import me.sarahlacerda.gua.identityservice.service.security.TokenRevocationService;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * Removes what this service holds about an account the authentication service has deleted, and leaves
 * the tombstone that keeps its user id from ever being issued again.
 *
 * <p>Invariants:
 * <ul>
 * <li>One transaction: every row of the account is deleted and the tombstone is written, or nothing
 * changes.</li>
 * <li>Idempotent: a repeat deletes nothing, rewrites the same tombstone and reports zero rows.</li>
 * <li>Redis state named after the account is dropped only after the commit, so a purge that rolls back
 * leaves the account exactly as it was. A failure there surfaces to the caller, whose retry repeats
 * the whole deletion.</li>
 * </ul>
 *
 * <p>{@link #PURGED_TABLES} and {@link #KEPT_TABLES} together name every table holding per-account data.
 * {@code AccountDeletionSchemaCoverageTest} fails when a migration adds such a table to neither.
 */
@Service
@RequiredArgsConstructor
public class AccountDeletionService {

    /** Tables from which the deletion removes every row of the account. */
    public static final Set<String> PURGED_TABLES = Set.of(
            "directory_entries", "identity_users", "passkey_credentials", "trusted_devices");

    /** Tables that keep a row for a deleted account, each with the reason it is kept. */
    public static final Map<String, String> KEPT_TABLES = Map.of(
            "account_genesis",
            "Tombstone, kept permanently: holds the user id, the internal account number, the origin and dates, "
                    + "and no phone, PIN, name or address. It keeps a deleted username from being given to "
                    + "someone else, who could then pose as the deleted person in old conversations.");

    private final IdentityUserRepository identityUserRepository;
    private final DirectoryEntryRepository directoryEntryRepository;
    private final PasskeyCredentialRepository passkeyCredentialRepository;
    private final TrustedDeviceRepository trustedDeviceRepository;
    private final PasskeyPrincipals passkeyPrincipals;
    private final AccountGenesisService accountGenesisService;
    private final TokenRevocationService tokenRevocationService;
    private final AccountReauthService accountReauthService;
    private final EndOtherSessionsService endOtherSessionsService;
    private final SecurityAuditLogger auditLogger;

    /** Rows removed by one deletion. All zero when the account held nothing here. */
    public record Purge(int directoryEntries, int securityRows, int passkeys, int trustedDevices) {
    }

    /**
     * Deletes the account's rows and tombstones it. Must be called through the Spring proxy: the after-commit
     * work is registered on the surrounding transaction, and registering refuses to run outside one.
     *
     * @param userId the deleted account's Matrix user id
     */
    @Transactional
    public Purge delete(String userId) {
        // Every completed sign-in locks this row before writing it, so one in flight either finishes
        // before the purge or waits, finds no row and is refused by the tombstone.
        identityUserRepository.findByUserIdForUpdate(userId);
        // Read before the tombstone is written: the principal resolves only while the row is attached.
        String passkeyPrincipal = passkeyPrincipals.forUserId(userId)
                .map(PasskeyPrincipals.Principal::text)
                .orElse(null);

        Purge purge = new Purge(
                directoryEntryRepository.deleteAllByUserId(userId),
                identityUserRepository.deleteAllByUserId(userId),
                passkeyCredentialRepository.deleteAllForAccount(userId, passkeyPrincipal),
                trustedDeviceRepository.deleteAllByUserId(userId));
        accountGenesisService.markDeleted(userId);

        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                auditLogger.accountDeleted(userId, purge.directoryEntries(), purge.securityRows(),
                        purge.passkeys(), purge.trustedDevices());
                tokenRevocationService.revokeAllTokensOfDeletedAccount(userId);
                accountReauthService.discardAttemptBudget(userId);
                endOtherSessionsService.discard(userId);
            }
        });
        return purge;
    }
}
