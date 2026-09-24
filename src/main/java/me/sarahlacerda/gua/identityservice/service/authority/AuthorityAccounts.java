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
 * The one file in this service that resolves an account's accountId from the authenticated user, and the
 * one response shape that publishes it back to its own account holder.
 *
 * <h2>Why it is one file</h2>
 *
 * <p>{@code AccountIdNotReadGuardTest} fails the build if any file outside a named allowed set so much as
 * writes the token. The hazard it guards is specific: MAS derives the Matrix localpart from an arbitrary
 * Jinja template over the imported claims, and an accountId is lowercase letters and digits, so a claim, a
 * userinfo field or a directory column carrying one would be a single config line away from re-keying
 * accounts. ADM-009 decision 12 states the implementation note that follows: the server resolves the
 * accountId from the authenticated user id through {@code account_genesis}, inside <em>one</em> new file
 * added to that test's allowed set, and the login path still never learns one.
 *
 * <p>So everything else in the authority feature speaks of an "account reference": the opaque 58-character
 * key of the chain rows and the 34 raw bytes the envelope carries. Only this class turns the authenticated
 * user id into either, and only this class publishes the value. The narrowness is the point, and it is
 * cheap: the chain never needs to parse an accountId, only to compare one.
 *
 * <h2>The rule of decision 3 rule 2</h2>
 *
 * <p>The accountId inside a submitted record must equal the one the server resolved from its own session
 * state, and the server reads none from the request. {@link #requireMatches(Resolved, byte[])} is that
 * check, in one place, so a record built for another account is refused whatever endpoint it arrives at.
 */
@Service
public class AuthorityAccounts {

    /** The 34 bytes the authority envelope carries at offset 6. */
    public static final int REFERENCE_LENGTH = AccountId.RAW_LENGTH;

    private final AccountGenesisRepository genesisRepository;

    public AuthorityAccounts(AccountGenesisRepository genesisRepository) {
        this.genesisRepository = genesisRepository;
    }

    /**
     * The account of the authenticated user.
     *
     * <p>Resolved from {@code account_genesis} by user id, which is the only join between an authenticated
     * MXID and an account object. An account with no genesis row has no accountId yet, so it has nothing
     * for a chain to be about; that is a 409 rather than a 404, because the account exists and the
     * bootstrap backfill is what gives it an id.
     */
    @Transactional(readOnly = true)
    public Resolved require(String userId) {
        AccountGenesisRecord row = genesisRepository.findByUserId(userId)
                .orElseThrow(() -> new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_no_account",
                        "This account has no account object yet."));
        return resolved(row);
    }

    /** The account of the authenticated user, or empty when it has no account object yet. */
    @Transactional(readOnly = true)
    public Optional<Resolved> find(String userId) {
        return genesisRepository.findByUserId(userId).map(AuthorityAccounts::resolved);
    }

    private static Resolved resolved(AccountGenesisRecord row) {
        AccountId parsed = AccountId.parse(row.getAccountId());
        return new Resolved(row.getUserId(), parsed.value(), parsed.rawBytes(), parsed.rootClass(),
                parsed.isGenesisRooted(), row.getAuthorityKeyB64(), committedRecoveryKey(row));
    }

    /**
     * The recovery authority key a class 0x01 accountId committed inside its genesis, base64url, or null.
     *
     * <p>Read back out of the stored canonical bytes rather than from a column, because no column holds it:
     * ADM-008 stored the genesis verbatim and read the recovery key only while decoding. That is the right
     * place for it to live, and this is the one caller that has ever needed it.
     */
    private static String committedRecoveryKey(AccountGenesisRecord row) {
        if (row.getOrigin() != AccountGenesisRecord.Origin.GENESIS || row.getGenesisB64() == null) {
            return null;
        }
        try {
            AccountGenesis genesis = AccountGenesisCodec.decode(
                    Base64.getUrlDecoder().decode(row.getGenesisB64()));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(genesis.recoveryAuthorityPublicKey());
        } catch (RuntimeException ex) {
            // A stored genesis that no longer decodes is a data problem, not a reason to hand out a null key
            // that would read as "this account committed none".
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_no_account",
                    "This account's account object cannot be read.");
        }
    }

    /**
     * Refuses a record whose envelope names another account (ADM-009 decision 3 rule 2).
     *
     * <p>A constant-time comparison, and the server's own value on the left: the reference in the request
     * is never used to look anything up, only to be compared against what the session already settled.
     */
    public void requireMatches(Resolved account, byte[] reference) {
        if (reference == null || reference.length != REFERENCE_LENGTH
                || !java.security.MessageDigest.isEqual(account.bytes(), reference)) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_account_mismatch",
                    "This record was not built for this account.");
        }
    }

    /**
     * The account, as the chain needs it.
     *
     * @param userId      the authenticated user the account was resolved from. Carried here so the code that
     *                    settles, extends or cancels a transition outside the submitting request still has an
     *                    account holder to notify: the chain rows are keyed on the reference, and a
     *                    notification needs the user
     * @param reference   the opaque key of every authority row for this account, which is the accountId's
     *                    canonical string form
     * @param rawReference the 34 bytes the record envelope carries
     * @param rootClass   the class byte inside the id
     * @param genesisRooted whether the id commits the account's first authority key. It records how the id
     *                    was derived and never whether the account holds authority today (ADM-009
     *                    decision 1): after an adoption a class 0x00 account holds authority its id does
     *                    not commit, and a verifier that needs to know reads the chain
     * @param committedAuthorityKeyB64 the authority key the accountId itself commits, base64url, or null on
     *                    a bootstrap account. A class 0x01 account's genesis authority key is its first
     *                    device key, committed by the id rather than by a record (ADM-009 decision 10)
     * @param committedRecoveryKeyB64 the recovery authority key that genesis committed, base64url, or null.
     *                    It is the key an {@code AuthorityRecovery} under authorization 0x01 must be signed
     *                    by on a class 0x01 account, which is what L13.1 means by a genesis-committed
     *                    threshold
     */
    public record Resolved(String userId, String reference, byte[] rawReference, byte rootClass,
            boolean genesisRooted, String committedAuthorityKeyB64, String committedRecoveryKeyB64) {

        /** Defensive copy, so no caller can edit the bytes a comparison will be made against. */
        public byte[] bytes() {
            return rawReference.clone();
        }

        /** {@code GENESIS} or {@code BOOTSTRAP}, as the published state reports it. */
        public String className() {
            return genesisRooted ? "GENESIS" : "BOOTSTRAP";
        }
    }

    /**
     * {@code GET /account/authority}, the one response in this service that returns an accountId, and only
     * ever to its own account holder.
     *
     * <p>It lives here rather than in the DTO package for the reason at the top of this class: this is the
     * single file allowed to name the identifier, and a response record that publishes it belongs on the
     * same side of that line as the code that resolves it. The client needs the value because it signs over
     * those 34 bytes.
     */
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

    /** One device key the chain has activated. */
    @Schema(description = "A device authority key and what the chain says about it")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record DeviceView(
            @Schema(description = "Raw 32-byte Ed25519 device authority key, base64url") String deviceKey,
            @Schema(description = "The label the granting record carried") String label,
            @Schema(description = "ACTIVE, QUARANTINED or REVOKED") String state,
            @Schema(description = "When the quarantine ends, while one is running") Long quarantineUntilEpochSeconds,
            @Schema(description = "The seq of the record that activated it") long grantedSeq) {
    }

    /** The transition holding a slot. */
    @Schema(description = "A transition inside its opposition window, which already holds its seq")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PendingView(
            @Schema(description = "ADOPT_ROOT, DEVICE_GRANT, DEVICE_REVOKE or AUTHORITY_RECOVERY") String type,
            @Schema(description = "The reserved position") long seq,
            @Schema(description = "When it completes if nobody objects") long effectiveAtEpochSeconds,
            @Schema(description = "SHA-256 hex of the pending record, which an opposition names")
            String recordHash) {
    }

    /** The five states of ADM-009 decision 10. A statement about keys, not about chain length. */
    public enum ChainState {
        /** Class 0x00, chain empty. Leaves by adoption start. */
        BOOTSTRAP,
        /** An AdoptRoot is held, its window running, its slot reserved. */
        ADOPTION_PENDING,
        /**
         * At least one unquarantined authority key, committed by the accountId or activated by a record.
         *
         * <p>A class 0x01 account is in this state from creation with an empty chain: its genesis
         * authority key is its first device key, committed by the id itself rather than by a record. That
         * is how a verifier tells such an account from a bootstrap one.
         */
        ROOTED,
        /** An AuthorityRecovery is held, its window running. */
        RECOVERY_PENDING,
        /** Rooted, no active device, no recovery key. Terminal by decision 7. */
        AUTHORITY_LOST;

        /** The name the wire uses. */
        public String wire() {
            return name();
        }
    }

    /** Zero-length reference, for the envelope of a record that names no account. Never accepted. */
    static byte[] emptyReference() {
        return new byte[AuthorityRecord.ACCOUNT_REFERENCE_LENGTH];
    }
}
