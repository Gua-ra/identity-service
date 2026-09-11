package me.sarahlacerda.gua.identityservice.service.account;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountGenesis;
import me.sarahlacerda.gua.identityservice.account.genesis.AccountGenesisCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesis;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesisCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.GenesisProofs;
import me.sarahlacerda.gua.identityservice.account.genesis.InvalidGenesisException;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.GenesisProperties;
import me.sarahlacerda.gua.identityservice.controller.dto.AccountGenesisRegisterResponse;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord.State;
import me.sarahlacerda.gua.identityservice.exception.GenesisRegistrationException;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;

/**
 * Registration, attach and bootstrap for account genesis (ADM-008 Phase 3).
 *
 * <p>Nothing here is read for routing or for login. The accountId is derived, stored and audited; it
 * never becomes a claim, a localpart or a directory column, because the MAS localpart template is
 * arbitrary Jinja over the imported claims, so any new claim is one config line away from becoming the
 * localpart (ADM-008 decision 10).
 */
@Service
@RequiredArgsConstructor
public class AccountGenesisService {

    private static final Logger log = LoggerFactory.getLogger(AccountGenesisService.class);

    private static final int ATTACH_HANDLE_LENGTH = 32;

    private final AccountGenesisRepository repository;
    private final IdentityServiceProperties properties;

    private final SecureRandom random = new SecureRandom();

    /** Master switch. While false the whole feature is inert and behaviour is exactly as before it existed. */
    public boolean isEnabled() {
        return genesisProperties().isEnabled();
    }

    /** Whether a native signup must present an attach handle rather than fall back to a bootstrap id. */
    public boolean isRequiredForNative() {
        return genesisProperties().isRequireForNative();
    }

    private GenesisProperties genesisProperties() {
        return properties.getGenesis();
    }

    // --- Registration ---------------------------------------------------------

    /**
     * Registers an {@code AccountGenesis} and returns its accountId with a single-use attach handle.
     *
     * <p>The proof is verified against the authority key committed inside the object itself, which is
     * what makes the endpoint self-authenticating at a point in the flow where no session exists yet.
     * Registering attaches nothing: a handle is a routing hint, not a capability.
     */
    @Transactional
    public AccountGenesisRegisterResponse register(String genesisB64, String proofB64) {
        if (!isEnabled()) {
            throw new GenesisRegistrationException(HttpStatus.SERVICE_UNAVAILABLE, "genesis_disabled",
                    "Account genesis registration is not enabled on this deployment.");
        }

        byte[] canonicalBytes = decodeBase64Url(genesisB64, "bad_genesis_encoding");
        AccountGenesis genesis = AccountGenesisCodec.decode(canonicalBytes);

        byte[] proof = decodeBase64Url(proofB64, "bad_proof_encoding");
        if (!GenesisProofs.verifyGenesisProof(genesis, proof)) {
            throw new GenesisRegistrationException(HttpStatus.BAD_REQUEST, "invalid_genesis_proof",
                    "The registration proof does not verify under the committed authority key.");
        }

        // ADM-008 decision 4. Framework 0x01 commits one recovery key and no delay bounds, and that key
        // shares the device store with the key it would veto, so production issuance waits on ADM-002.
        if (genesis.recoveryFrameworkId() == AccountGenesis.RECOVERY_FRAMEWORK_COMMITTED_KEY
                && !genesisProperties().isProductionIssuance()) {
            throw new GenesisRegistrationException(HttpStatus.FORBIDDEN, "genesis_issuance_not_permitted",
                    "Issuance under recovery framework 0x01 is not permitted on this deployment.");
        }

        AccountId accountId = genesis.accountId();
        Instant now = Instant.now();
        Instant expiresAt = now.plus(genesisProperties().getPendingTtl());
        String handle = newAttachHandle();

        Optional<AccountGenesisRecord> existing = repository.findById(accountId.value());
        if (existing.isPresent()) {
            AccountGenesisRecord row = existing.get();
            if (row.isAttached()) {
                // The client must generate a fresh genesis; re-using one that already owns an account
                // would be an attempt to re-point it.
                throw new GenesisRegistrationException(HttpStatus.CONFLICT, "genesis_already_attached",
                        "This genesis is already attached to an account.");
            }
            // Re-registering the same bytes while pending rotates the handle and the window.
            row.setAttachHandleHash(sha256Hex(handle));
            row.setExpiresAt(expiresAt);
            repository.save(row);
            log.info("Rotated the attach handle of a pending genesis registration");
        } else {
            repository.save(AccountGenesisRecord.pendingGenesis(
                    accountId.value(),
                    (short) genesis.genesisVersion(),
                    (short) genesis.suite(),
                    encodeBase64Url(genesis.canonicalBytes()),
                    encodeBase64Url(genesis.authorityPublicKey()),
                    sha256Hex(handle),
                    expiresAt));
            log.info("Registered a pending account genesis");
        }

        return new AccountGenesisRegisterResponse(accountId.value(), handle, expiresAt);
    }

    // --- Attach ---------------------------------------------------------------

    /**
     * Issues the 32 CSPRNG bytes a client must sign to attach its genesis, base64url.
     *
     * <p>They are held against the server-side login session and are never accepted back from the client
     * as a lookup key: the attach reads them from the session, not from the request.
     */
    public String issueAttachChallenge() {
        byte[] challenge = new byte[GenesisProofs.ATTACH_CHALLENGE_LENGTH];
        random.nextBytes(challenge);
        return encodeBase64Url(challenge);
    }

    /**
     * Attaches a registered genesis to a newly created account, inside the caller's transaction.
     *
     * <p>{@link Propagation#MANDATORY} is the point: ADM-008 decision 6 requires the verification to
     * happen inside the account-creation transaction, so this refuses to run outside one. A failure here
     * therefore rolls the account back with it, rather than leaving an account attached to nothing or a
     * genesis attached to an account that was never written.
     *
     * @param attachHandle the handle carried by the login session, never one read from the request body
     * @param challengeB64 the challenge held against that session, never one supplied by the client
     * @param proofB64     the client's signature over the domain, the challenge and the raw accountId
     * @param userId       the MXID of the account being created
     * @return the attached accountId
     * @throws LoginFlowException 400 {@code genesis_attach_failed} for every failure mode; a handle that
     *                            was presented and did not attach fails the signup, with no silent
     *                            downgrade to a bootstrap id
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public AccountId attach(String attachHandle, String challengeB64, String proofB64, String userId) {
        if (!StringUtils.hasText(attachHandle)) {
            throw attachFailed("no attach handle on the session");
        }
        AccountGenesisRecord row = repository.findByAttachHandleHash(sha256Hex(attachHandle))
                .orElseThrow(() -> attachFailed("no pending registration for this handle"));
        if (row.getState() != State.PENDING) {
            throw attachFailed("the registration is no longer pending");
        }
        if (row.getExpiresAt() == null || !row.getExpiresAt().isAfter(Instant.now())) {
            throw attachFailed("the registration has expired");
        }
        if (!StringUtils.hasText(challengeB64)) {
            throw attachFailed("no attach challenge was issued for this session");
        }
        if (!StringUtils.hasText(proofB64)) {
            throw attachFailed("no attach proof was presented");
        }

        byte[] challenge;
        byte[] proof;
        try {
            challenge = decodeBase64Url(challengeB64, "bad_challenge_encoding");
            proof = decodeBase64Url(proofB64, "bad_attach_proof_encoding");
        } catch (InvalidGenesisException ex) {
            throw attachFailed("the attach proof is not base64url");
        }
        if (challenge.length != GenesisProofs.ATTACH_CHALLENGE_LENGTH) {
            throw attachFailed("the stored challenge is the wrong length");
        }

        // The accountId is derived from the STORED genesis. None is read from the request, so a client
        // cannot name one account while signing for another.
        AccountGenesis genesis;
        try {
            genesis = AccountGenesisCodec.decode(decodeBase64Url(row.getGenesisB64(), "stored_genesis_unreadable"));
        } catch (InvalidGenesisException ex) {
            log.error("Stored genesis for {} no longer decodes: {}", row.getAccountId(), ex.reason());
            throw attachFailed("the stored genesis is unreadable");
        }
        AccountId accountId = genesis.accountId();
        if (!accountId.value().equals(row.getAccountId())) {
            log.error("Stored genesis bytes do not re-derive the stored accountId");
            throw attachFailed("the stored genesis does not match its accountId");
        }

        if (!GenesisProofs.verifyAttachProof(genesis.authorityPublicKey(), challenge, accountId, proof)) {
            throw attachFailed("the attach proof does not verify");
        }

        // One atomic compare-and-set. Two sessions racing on one handle therefore resolve to a single
        // attach: the loser updates no rows and its signup fails.
        int updated = repository.attach(accountId.value(), sha256Hex(attachHandle), userId, Instant.now(),
                State.PENDING, State.ATTACHED);
        if (updated != 1) {
            throw attachFailed("the registration was attached by another session");
        }
        log.info("Attached a genesis-rooted accountId to a new account");
        return accountId;
    }

    /**
     * Mints a bootstrap accountId for an account that presented no handle (ADM-001 L5 path B1).
     *
     * <p>Idempotent: an account that already holds a genesis row keeps it, so this is safe on a retry
     * and safe to call from the backfill.
     *
     * @return the accountId now held by the account
     */
    @Transactional
    public AccountId bootstrap(String userId) {
        Optional<AccountGenesisRecord> existing = repository.findByUserId(userId);
        if (existing.isPresent()) {
            return AccountId.parse(existing.get().getAccountId());
        }
        // Random entropy, never the MXID or the phone: a preimage containing either would put an
        // identifier, and with it the homeserver, inside the id (ADM-001 L4, L15).
        BootstrapGenesis genesis = BootstrapGenesisCodec.mint();
        AccountId accountId = genesis.accountId();
        repository.save(AccountGenesisRecord.attachedBootstrap(
                accountId.value(),
                userId,
                (short) genesis.version(),
                (short) genesis.suite(),
                encodeBase64Url(genesis.canonicalBytes()),
                Instant.now()));
        return accountId;
    }

    /** Deletes pending registrations nobody attached inside their window. */
    @Transactional
    public int sweepExpired() {
        return repository.deleteExpiredPending(State.PENDING, Instant.now());
    }

    private static LoginFlowException attachFailed(String reason) {
        // The reason is logged, never returned: a caller learns only that the attach failed.
        log.warn("Genesis attach refused: {}", reason);
        return new LoginFlowException(HttpStatus.BAD_REQUEST, "genesis_attach_failed",
                "This account could not be created. Please try again.");
    }

    private String newAttachHandle() {
        byte[] bytes = new byte[ATTACH_HANDLE_LENGTH];
        random.nextBytes(bytes);
        return encodeBase64Url(bytes);
    }

    private static String encodeBase64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] decodeBase64Url(String value, String reason) {
        if (!StringUtils.hasText(value)) {
            throw new InvalidGenesisException(reason, "value is missing");
        }
        try {
            return Base64.getUrlDecoder().decode(value.trim());
        } catch (IllegalArgumentException ex) {
            throw new InvalidGenesisException(reason, "value is not base64url", ex);
        }
    }

    /** SHA-256 hex of an attach handle. Only the hash is ever stored. */
    static String sha256Hex(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable in this JVM", ex);
        }
    }
}
