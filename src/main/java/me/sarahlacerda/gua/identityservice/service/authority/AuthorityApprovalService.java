// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityProofs;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityDevice;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceRepository;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityAccounts.Resolved;

/**
 * A browser session can only start an approval; an active authority device must sign it. Approvals live
 * in Redis and are single use.
 */
@Service
public class AuthorityApprovalService {

    private static final String KEY_PREFIX = "authority:approval:";
    private static final String INDEX_PREFIX = "authority:approval:account:";

    private static final char[] CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ2346789".toCharArray();

    private static final int CODE_LENGTH = 4;

    private final org.springframework.data.redis.core.StringRedisTemplate redisTemplate;
    private final AuthorityPolicy policy;
    private final AuthorityDeviceRepository deviceRepository;
    private final SecureRandom random = new SecureRandom();

    public AuthorityApprovalService(org.springframework.data.redis.core.StringRedisTemplate redisTemplate,
            AuthorityPolicy policy, AuthorityDeviceRepository deviceRepository) {
        this.redisTemplate = redisTemplate;
        this.policy = policy;
        this.deviceRepository = deviceRepository;
    }

    /**
     * The action digest is derived here and never taken from the caller, so the text shown and the bytes
     * signed cannot differ.
     */
    public Started start(Resolved account, String actionId, Instant now) {
        policy.requireEnabled();
        if (!StringUtils.hasText(actionId)) {
            throw new AuthorityTransitionException(HttpStatus.BAD_REQUEST, "authority_approval_invalid",
                    "an approval names the action it is for");
        }
        String action = actionId.trim();
        byte[] actionDigest = digestOf(action);

        List<Approval> live = live(account, now);
        if (live.size() >= policy.maxLiveApprovals()) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_approval_limit",
                    "There are already too many requests waiting for your approval.");
        }
        Set<String> taken = new java.util.HashSet<>();
        live.forEach(approval -> taken.add(approval.code()));

        byte[] id = new byte[AuthorityProofs.APPROVAL_ID_LENGTH];
        random.nextBytes(id);
        byte[] challenge = new byte[AuthorityRecord.CHALLENGE_LENGTH];
        random.nextBytes(challenge);
        String code = uniqueCode(taken);
        Instant expiresAt = now.plus(policy.approvalTtl());

        String approvalId = encode(id);
        String value = String.join("|", account.reference(), approvalId, code, action,
                encode(actionDigest), encode(challenge), Long.toString(expiresAt.getEpochSecond()));
        redisTemplate.opsForValue().set(KEY_PREFIX + approvalId, value, policy.approvalTtl());
        redisTemplate.opsForSet().add(INDEX_PREFIX + account.reference(), approvalId);
        redisTemplate.expire(INDEX_PREFIX + account.reference(), policy.approvalTtl());

        return new Started(approvalId, code, encode(challenge), expiresAt);
    }

    public List<Approval> live(Resolved account, Instant now) {
        Set<String> ids = redisTemplate.opsForSet().members(INDEX_PREFIX + account.reference());
        List<Approval> approvals = new ArrayList<>();
        if (ids == null) {
            return approvals;
        }
        for (String id : ids) {
            read(id).filter(approval -> approval.expiresAt().isAfter(now)).ifPresent(approvals::add);
        }
        approvals.sort(java.util.Comparator.comparing(Approval::expiresAt));
        return approvals;
    }

    /** Burns the approval before checking the signature, so a refused attempt cannot be retried. */
    public void sign(Resolved account, String approvalId, String signatureB64, Instant now) {
        policy.requireEnabled();
        Approval approval = read(approvalId)
                .filter(candidate -> candidate.account().equals(account.reference()))
                .filter(candidate -> candidate.expiresAt().isAfter(now))
                .orElseThrow(() -> refused());
        burn(account, approvalId);

        byte[] signature = decode(signatureB64, 64, "a signature");
        boolean verified = false;
        for (AuthorityDevice device : deviceRepository.findByAccount(account.reference())) {
            if (!device.isUnquarantinedActive(now) || device.getState() == AuthorityDevice.State.REVOKED) {
                continue;
            }
            if (AuthorityProofs.verifyApproval(decodeKey(device.getDeviceKeyB64()), account.bytes(),
                    decode(approval.id(), AuthorityProofs.APPROVAL_ID_LENGTH, "an approval id"),
                    decode(approval.actionDigest(), AuthorityRecord.HASH_LENGTH, "an action digest"),
                    decode(approval.challenge(), AuthorityRecord.CHALLENGE_LENGTH, "a challenge"), signature)) {
                verified = true;
                break;
            }
        }
        if (!verified) {
            throw refused();
        }
    }

    private void burn(Resolved account, String approvalId) {
        redisTemplate.delete(KEY_PREFIX + approvalId);
        redisTemplate.opsForSet().remove(INDEX_PREFIX + account.reference(), approvalId);
    }

    private Optional<Approval> read(String approvalId) {
        if (!StringUtils.hasText(approvalId)) {
            return Optional.empty();
        }
        String value = redisTemplate.opsForValue().get(KEY_PREFIX + approvalId);
        if (value == null) {
            return Optional.empty();
        }
        String[] parts = value.split("\\|", 7);
        if (parts.length != 7) {
            return Optional.empty();
        }
        return Optional.of(new Approval(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5],
                Instant.ofEpochSecond(Long.parseLong(parts[6]))));
    }

    private String uniqueCode(Set<String> taken) {
        for (int attempt = 0; attempt < 64; attempt++) {
            StringBuilder code = new StringBuilder(CODE_LENGTH);
            for (int i = 0; i < CODE_LENGTH; i++) {
                code.append(CODE_ALPHABET[random.nextInt(CODE_ALPHABET.length)]);
            }
            if (taken.add(code.toString())) {
                return code.toString();
            }
        }
        throw new IllegalStateException("could not mint a distinct approval code");
    }

    static byte[] digestOf(String actionId) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256")
                    .digest(actionId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable in this JVM", ex);
        }
    }

    private static AuthorityTransitionException refused() {
        // One refusal for every failure, so the caller cannot tell them apart.
        return new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_approval_invalid",
                "That request could not be approved.");
    }

    private static String encode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] decode(String value, int length, String what) {
        try {
            byte[] raw = Base64.getUrlDecoder().decode(value);
            if (raw.length != length) {
                throw new AuthorityTransitionException(HttpStatus.BAD_REQUEST, "authority_approval_invalid",
                        what + " is " + length + " bytes");
            }
            return raw;
        } catch (IllegalArgumentException ex) {
            throw new AuthorityTransitionException(HttpStatus.BAD_REQUEST, "authority_approval_invalid",
                    what + " is not base64url");
        }
    }

    private static byte[] decodeKey(String deviceKeyB64) {
        return Base64.getUrlDecoder().decode(deviceKeyB64);
    }

    public record Approval(String account, String id, String code, String action, String actionDigest,
            String challenge, Instant expiresAt) {
    }

    public record Started(String approvalId, String code, String challenge, Instant expiresAt) {
    }
}
