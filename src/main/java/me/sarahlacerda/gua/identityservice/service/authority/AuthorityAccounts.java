// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.swagger.v3.oas.annotations.media.Schema;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecord;
import me.sarahlacerda.gua.identityservice.account.genesis.AccountGenesis;
import me.sarahlacerda.gua.identityservice.account.genesis.AccountGenesisCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;

/**
 * The only authority class allowed to resolve an accountId (AccountIdNotReadGuardTest). Everything else
 * handles an opaque account reference.
 */
@Service
public class AuthorityAccounts {

    public static final int REFERENCE_LENGTH = AccountId.RAW_LENGTH;

    private final AccountGenesisRepository genesisRepository;

    public AuthorityAccounts(AccountGenesisRepository genesisRepository) {
        this.genesisRepository = genesisRepository;
    }

    @Transactional(readOnly = true)
    public Resolved require(String userId) {
        AccountGenesisRecord row = genesisRepository.findByUserId(userId)
                .orElseThrow(() -> new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_no_account",
                        "This account has no account object yet."));
        return resolved(row);
    }

    @Transactional(readOnly = true)
    public Optional<Resolved> find(String userId) {
        return genesisRepository.findByUserId(userId).map(AuthorityAccounts::resolved);
    }

    private static Resolved resolved(AccountGenesisRecord row) {
        AccountId parsed = AccountId.parse(row.getAccountId());
        return new Resolved(row.getUserId(), parsed.value(), parsed.rawBytes(), parsed.rootClass(),
                parsed.isGenesisRooted(), row.getAuthorityKeyB64(), committedRecoveryKey(row));
    }

    private static String committedRecoveryKey(AccountGenesisRecord row) {
        if (row.getOrigin() != AccountGenesisRecord.Origin.GENESIS || row.getGenesisB64() == null) {
            return null;
        }
        try {
            AccountGenesis genesis = AccountGenesisCodec.decode(
                    Base64.getUrlDecoder().decode(row.getGenesisB64()));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(genesis.recoveryAuthorityPublicKey());
        } catch (RuntimeException ex) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_no_account",
                    "This account's account object cannot be read.");
        }
    }

    public void requireMatches(Resolved account, byte[] reference) {
        if (reference == null || reference.length != REFERENCE_LENGTH
                || !java.security.MessageDigest.isEqual(account.bytes(), reference)) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_account_mismatch",
                    "This record was not built for this account.");
        }
    }

    /** {@code genesisRooted} says how the id was derived, not whether the account holds authority today. */
    public record Resolved(String userId, String reference, byte[] rawReference, byte rootClass,
            boolean genesisRooted, String committedAuthorityKeyB64, String committedRecoveryKeyB64) {

        public byte[] bytes() {
            return rawReference.clone();
        }

        public String className() {
            return genesisRooted ? "GENESIS" : "BOOTSTRAP";
        }
    }

    /** Lives here rather than in the DTO package because it is the only response that carries an accountId. */
    @Schema(description = "The account's authority chain, its device set and any pending transition")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AuthorityStateResponse(
            @Schema(description = "The account's permanent accountId, 58 characters") String accountId,
            @Schema(description = "BOOTSTRAP or GENESIS: how the id was derived, never whether the account "
                    + "holds authority today") String accountClass,
            @Schema(description = "BOOTSTRAP, ADOPTION_PENDING, ROOTED, RECOVERY_PENDING or AUTHORITY_LOST")
            String state,
            @Schema(description = "Position of the last accepted record; 0 while the chain is empty")
            long headSeq,
            @Schema(description = "SHA-256 hex of the last accepted record; 64 zeros while empty")
            String headHash,
            List<DeviceView> devices,
            @Schema(description = "The transition inside its window, or null") PendingView pending) {
    }

    @Schema(description = "A device authority key and what the chain says about it")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record DeviceView(
            @Schema(description = "Raw 32-byte Ed25519 device authority key, base64url") String deviceKey,
            @Schema(description = "The label the granting record carried") String label,
            @Schema(description = "ACTIVE, QUARANTINED or REVOKED") String state,
            @Schema(description = "When the quarantine ends, while one is running") Long quarantineUntilEpochSeconds,
            @Schema(description = "The seq of the record that activated it") long grantedSeq) {
    }

    @Schema(description = "A transition inside its opposition window, which already holds its seq")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PendingView(
            @Schema(description = "ADOPT_ROOT, DEVICE_GRANT, DEVICE_REVOKE or AUTHORITY_RECOVERY") String type,
            @Schema(description = "The reserved position") long seq,
            @Schema(description = "When it completes if nobody objects") long effectiveAtEpochSeconds,
            @Schema(description = "SHA-256 hex of the pending record, which an opposition names")
            String recordHash,
            @Schema(description = "SHA-256 hex of the record before it, which an Oppose signs over. An "
                    + "objection takes no slot, so it stands at the opposed record's own seq and prevHash and "
                    + "is checked against both; this is the only place a device that did not build that record "
                    + "can learn this value, because placing it made its hash the head")
            String prevHash) {
    }

    public enum ChainState {
        BOOTSTRAP,
        ADOPTION_PENDING,
        /** Includes a genesis-rooted account whose chain is still empty. */
        ROOTED,
        RECOVERY_PENDING,
        AUTHORITY_LOST;

        public String wire() {
            return name();
        }
    }

    static byte[] emptyReference() {
        return new byte[AuthorityRecord.ACCOUNT_REFERENCE_LENGTH];
    }
}
