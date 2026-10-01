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

/** Only the SHA-256 of a challenge is stored. Each is single use and bound to one account and session. */
@Service
public class AuthorityChallengeService {

    private static final Logger log = LoggerFactory.getLogger(AuthorityChallengeService.class);

    private final AuthorityChallengeRepository repository;
    private final AuthorityPolicy policy;
    private final AuthorityChallengeBurn burn;
    private final SecureRandom random = new SecureRandom();

    public AuthorityChallengeService(AuthorityChallengeRepository repository, AuthorityPolicy policy,
            AuthorityChallengeBurn burn) {
        this.repository = repository;
        this.policy = policy;
        this.burn = burn;
    }

    @Transactional
    public Minted mint(String account, String sessionHash, Purpose purpose, AuthFactor factor,
            Instant factorCreatedAt, Instant now) {
        byte[] challenge = new byte[AuthorityRecord.CHALLENGE_LENGTH];
        random.nextBytes(challenge);
        String value = encode(challenge);
        Instant expiresAt = now.plus(policy.challengeTtl());

        repository.save(AuthorityChallenge.minted(account, sessionHash, purpose, sha256Hex(value), factor,
                factorCreatedAt, expiresAt, now));

        repository.deleteExpired(now);

        return new Minted(value, expiresAt);
    }

    /**
     * Burns the challenge before the record is verified, through {@link AuthorityChallengeBurn}, so a refusal
     * cannot leave it spendable.
     */
    @Transactional
    public Spent spend(String account, String sessionHash, Purpose purpose, String challengeB64, Instant now) {
        if (!StringUtils.hasText(challengeB64)) {
            throw refused("no challenge was presented");
        }
        AuthorityChallenge row = repository.findByChallengeHash(sha256Hex(challengeB64.trim()))
                .orElseThrow(() -> refused("no such challenge"));

        // One refusal for every mismatch, so the caller cannot learn which binding failed.
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

        if (!burn.burn(row.getChallengeHash(), now)) {
            throw refused("the challenge was spent by another request");
        }
        return new Spent(decode(challengeB64.trim()), row.getFactor(), row.getFactorCreatedAt());
    }

    public record Spent(byte[] challenge, AuthFactor factor, Instant factorCreatedAt) {
    }

    @Transactional
    public void burnUnspent(String account, Purpose purpose, Instant now) {
        for (AuthorityChallenge row : repository.findByAccountAndPurposeAndSpentAtIsNull(account, purpose)) {
            row.setSpentAt(now);
            repository.save(row);
        }
    }

    @Transactional(readOnly = true)
    public java.util.Optional<AuthorityChallenge> find(String challengeB64) {
        if (!StringUtils.hasText(challengeB64)) {
            return java.util.Optional.empty();
        }
        return repository.findByChallengeHash(sha256Hex(challengeB64.trim()));
    }

    private AuthorityTransitionException refusedAfterBurning(AuthorityChallenge row, Instant now, String reason) {
        burn.burn(row.getChallengeHash(), now);
        return refused(reason);
    }

    private static AuthorityTransitionException refused(String reason) {
        log.warn("Authority challenge refused: {}", reason);
        return new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_challenge_invalid",
                "That confirmation has expired. Please start again.");
    }

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

    public record Minted(String challenge, Instant expiresAt) {
    }
}
