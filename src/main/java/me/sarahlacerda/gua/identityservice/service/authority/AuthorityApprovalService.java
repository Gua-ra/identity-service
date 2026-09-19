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
 * Authority-sensitive actions reached from a browser (ADM-009 decision 6).
 *
 * <p>A browser login grants account access. It never enters the device set, and no browser-held material may
 * sign an authority record. This is a rule, not a default: there is no flag that lets a web session sign one.
 *
 * <p>What a web session may do instead is create a pending approval carrying the account, the action digest
 * and a 32-byte server challenge. The browser displays a four-character code from an alphabet with no
 * look-alike characters; an active authority device fetches the approval, shows the same code and the action
 * in the reader's own words, and signs it. The browser never learns a key and never proxies one.
 *
 * <p>A malicious page can therefore start an approval the user never wanted, which is exactly what the code
 * and the device-side description defend: the approval names the action on a screen the page does not control.
 *
 * <p>Held in Redis rather than in a table, like every other short-lived single-use ceremony here. An approval
 * expires in ten minutes, is single use, and its challenge is burned on refusal as well as on acceptance.
 */
@Service
public class AuthorityApprovalService {

    private static final String KEY_PREFIX = "authority:approval:";
    private static final String INDEX_PREFIX = "authority:approval:account:";

    /**
     * No look-alike characters, so a reader comparing two screens is never asked to tell {@code O} from
     * {@code 0} or {@code I} from {@code 1}. The code is the whole of what binds the two screens together.
     */
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
     * Starts an approval from the session that wants the action, browser or not.
     *
     * <p>At most three live per account, and a code unique among them, because the code is what a reader
     * compares: two live approvals showing the same four characters would make the comparison meaningless.
     */
    public Started start(Resolved account, String actionId, String actionDigestB64, Instant now) {
        policy.requireEnabled();
        byte[] actionDigest = decode(actionDigestB64, AuthorityRecord.HASH_LENGTH, "an action digest");

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
        String value = String.join("|", account.reference(), approvalId, code, actionId == null ? "" : actionId,
                encode(actionDigest), encode(challenge), Long.toString(expiresAt.getEpochSecond()));
        redisTemplate.opsForValue().set(KEY_PREFIX + approvalId, value, policy.approvalTtl());
        redisTemplate.opsForSet().add(INDEX_PREFIX + account.reference(), approvalId);
        redisTemplate.expire(INDEX_PREFIX + account.reference(), policy.approvalTtl());

        return new Started(approvalId, code, encode(challenge), expiresAt);
    }

    /** The live approvals for the account, at most three, for an authority device to show and sign. */
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

    /**
     * Accepts one device's signature over exactly this approval, and burns it.
     *
     * <p>Burned before the signature is weighed, so a refusal consumes the approval too: an approval is
     * single use, and a caller that may retry it is a caller that may grind the four-character code.
     */
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
                // A quarantined device may not sign an authority-sensitive approval, and a revoked one is not
                // this account's authority at all.
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

    private static AuthorityTransitionException refused() {
        // One refusal for an unknown id, an expired one, another account's, and a signature that does not
        // verify, so a caller learns nothing from the difference.
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

    /**
     * A live approval, as a device sees it.
     *
     * @param code the four characters the browser is also showing
     */
    public record Approval(String account, String id, String code, String action, String actionDigest,
            String challenge, Instant expiresAt) {
    }

    /** What the browser session is handed. */
    public record Started(String approvalId, String code, String challenge, Instant expiresAt) {
    }
}
