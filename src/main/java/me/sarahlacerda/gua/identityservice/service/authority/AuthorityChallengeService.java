// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChallengeRepository;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;

/**
 * The server challenge every authority record signs (ADM-009 decision 2).
 *
 * <p>32 CSPRNG bytes, minted once, held against the account and the acting stepped-up session, single use,
 * burned on acceptance <em>and</em> on refusal, expiring at or under 15 minutes.
 *
 * <p>Only the SHA-256 of the challenge is stored, the way {@code account_genesis} stores only the hash of an
 * attach handle. The value is returned once and never again, so a dump of this table hands nobody something
 * to sign. Lookup therefore starts from the bytes the caller returned, which is also what makes holding a
 * challenge mean something: a caller that did not receive these bytes cannot find the row.
 *
 * <p>Why this is worth the table at all, rather than a signature over the record alone: a record signed with
 * no server input is a precomputable, transferable artifact that proves possession of a key and nothing
 * about when or where its holder was. That is the freshness defect ADM-008:151 already records against the
 * genesis registration proof, and repeating it here would make a captured request body replayable after the
 * owner had opposed it.
 */
@Service
public class AuthorityChallengeService {

    private static final Logger log = LoggerFactory.getLogger(AuthorityChallengeService.class);

    private final AuthorityChallengeRepository repository;
    private final AuthorityPolicy policy;
    private final SecureRandom random = new SecureRandom();

    public AuthorityChallengeService(AuthorityChallengeRepository repository, AuthorityPolicy policy) {
        this.repository = repository;
        this.policy = policy;
    }

    /**
     * Mints a challenge for one transition, and returns it base64url. The only time the value exists outside
     * the caller's request.
     *
     * @param factor          which step-up settled it, so the hold is weighed on the factor presented
     * @param factorCreatedAt when that credential came into being; null when the purpose asks for no factor
     */
    @Transactional
    public Minted mint(String account, String sessionHash, Purpose purpose, AuthFactor factor,
            Instant factorCreatedAt, Instant now) {
        byte[] challenge = new byte[AuthorityRecord.CHALLENGE_LENGTH];
        random.nextBytes(challenge);
        String value = encode(challenge);
        Instant expiresAt = now.plus(policy.challengeTtl());

        repository.save(AuthorityChallenge.minted(account, sessionHash, purpose, sha256Hex(value), factor,
                factorCreatedAt, expiresAt, now));

        // Housekeeping on the write path rather than a scheduled job, exactly as the genesis sweep does and
        // for the same reason: nothing in this application enables scheduling, and an expired challenge is
        // already refused when it is spent, so this only stops them piling up.
        repository.deleteExpired(now);

        return new Minted(value, expiresAt);
    }

    /**
     * Spends a challenge and returns its 32 bytes, so the caller can build the preimage the record is
     * verified against.
     *
     * <p>Burned before the record is verified, on purpose. "Single use, burned on acceptance and on refusal"
     * is not a description of two code paths, it is one: marking it spent here means no arrangement of later
     * failures can leave it spendable, and a caller whose record was refused asks for a new challenge rather
     * than retrying against the old one.
     */
    @Transactional
    public Spent spend(String account, String sessionHash, Purpose purpose, String challengeB64, Instant now) {
        if (!StringUtils.hasText(challengeB64)) {
            throw refused("no challenge was presented");
        }
        AuthorityChallenge row = repository.findByChallengeHash(sha256Hex(challengeB64.trim()))
                .orElseThrow(() -> refused("no such challenge"));

        // Every mismatch is the same refusal, so a caller cannot learn from the error which of the four
        // bindings it got wrong.
        if (!row.getAccount().equals(account)) {
            throw refusedAfterBurning(row, now, "the challenge belongs to another account");
        }
        if (!MessageDigest.isEqual(row.getSessionHash().getBytes(StandardCharsets.US_ASCII),
                sessionHash.getBytes(StandardCharsets.US_ASCII))) {
            throw refusedAfterBurning(row, now, "the challenge was minted for another session");
        }
        if (row.getPurpose() != purpose) {
            throw refusedAfterBurning(row, now, "the challenge was minted for another purpose");
        }
        if (!row.isSpendable(now)) {
            throw refused("the challenge is spent or expired");
        }

        row.setSpentAt(now);
        repository.save(row);
        return new Spent(decode(challengeB64.trim()), row.getFactor(), row.getFactorCreatedAt());
    }

    /**
     * A spent challenge: its bytes, and which step-up minted it.
     *
     * <p>The factor travels with the challenge so the transition weighs the hold on the credential actually
     * presented, rather than on whatever the account happens to hold by the time the record arrives. Those
     * can differ by minutes, and the difference is exactly the attack: mint a factor, spend it at once.
     */
    public record Spent(byte[] challenge, AuthFactor factor, Instant factorCreatedAt) {
    }

    /** Burns every unspent challenge of one purpose, which is what cancelling a transition owes. */
    @Transactional
    public void burnUnspent(String account, Purpose purpose, Instant now) {
        for (AuthorityChallenge row : repository.findByAccountAndPurposeAndSpentAtIsNull(account, purpose)) {
            row.setSpentAt(now);
            repository.save(row);
        }
    }

    /** The factor a spent challenge was minted on, which the transition weighs the hold against. */
    @Transactional(readOnly = true)
    public java.util.Optional<AuthorityChallenge> find(String challengeB64) {
        if (!StringUtils.hasText(challengeB64)) {
            return java.util.Optional.empty();
        }
        return repository.findByChallengeHash(sha256Hex(challengeB64.trim()));
    }

    private AuthorityTransitionException refusedAfterBurning(AuthorityChallenge row, Instant now, String reason) {
        row.setSpentAt(now);
        repository.save(row);
        return refused(reason);
    }

    private static AuthorityTransitionException refused(String reason) {
        // The reason is logged, never returned: a caller learns only that the challenge did not hold.
        log.warn("Authority challenge refused: {}", reason);
        return new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_challenge_invalid",
                "That confirmation has expired. Please start again.");
    }

    /** SHA-256 of the bearer token, which is what binds a challenge to one acting session. */
    public static String sessionHash(String bearerToken) {
        return sha256Hex(bearerToken == null ? "" : bearerToken);
    }

    static String sha256Hex(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable in this JVM", ex);
        }
    }

    private static String encode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] decode(String value) {
        try {
            byte[] raw = Base64.getUrlDecoder().decode(value);
            if (raw.length != AuthorityRecord.CHALLENGE_LENGTH) {
                throw refused("the challenge is the wrong length");
            }
            return raw;
        } catch (IllegalArgumentException ex) {
            throw refused("the challenge is not base64url");
        }
    }

    /**
     * A freshly minted challenge.
     *
     * @param challenge base64url, returned once
     * @param expiresAt when it stops being spendable, which is also the age limit on the step-up that
     *                  minted it
     */
    public record Minted(String challenge, Instant expiresAt) {
    }
}
