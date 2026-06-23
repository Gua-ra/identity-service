package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneChangeChallengeException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.MatrixProvisioningService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberMasker;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberNormalizer;
import me.sarahlacerda.gua.identityservice.service.routing.ResolverDirectoryClient;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * Two-step orchestration for changing an account's verified phone number.
 *
 * <p>
 * Security posture (see {@code FINAL DESIGN}):
 * <ul>
 * <li><b>/start</b> is gated by a {@code PHONE_CHANGE}-scoped, single-use reauth
 * token <em>and</em> a non-phone step-up factor (account PIN when set and/or a
 * passkey assertion). The reauth token alone proves only a current-phone OTP,
 * which a SIM-swap attacker could control — hence the extra factor.</li>
 * <li>The new-number OTP is namespaced per challenge
 * ({@link PhoneChangeOtpService}) so the public {@code /otp/send} cannot
 * overwrite or race it.</li>
 * <li>{@code /complete} enforces an IP-independent per-challenge wrong-OTP cap,
 * then performs one atomic directory swap that carries
 * displayName/discoverable/username/homeserverId forward, then post-commit
 * registers the new / unregisters the old number, revokes all tokens, audits and
 * notifies.</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
public class PhoneChangeService {

    private static final Logger log = LoggerFactory.getLogger(PhoneChangeService.class);

    private static final String CHALLENGE_KEY_PREFIX = "phone:change:";

    private final IdentityServiceProperties properties;
    private final StringRedisTemplate redisTemplate;
    private final AccountReauthService reauthService;
    private final UserSecurityService userSecurityService;
    private final PasskeyService passkeyService;
    private final PhoneChangeOtpService phoneChangeOtpService;
    private final PhoneNumberNormalizer phoneNumberNormalizer;
    private final PhoneNumberHasher phoneNumberHasher;
    private final PhoneNumberMasker phoneNumberMasker;
    private final DirectoryService directoryService;
    private final PhoneDirectorySwapService phoneDirectorySwapService;
    private final MatrixProvisioningService matrixProvisioningService;
    private final ResolverDirectoryClient resolverDirectoryClient;
    private final TokenRevocationService tokenRevocationService;
    private final SecurityAuditLogger auditLogger;
    private final DeviceNotificationService deviceNotificationService;

    /**
     * Step 1: gate with op-scoped reauth + step-up, normalize and validate the new
     * number, send a challenge-namespaced OTP to it, alert the OLD number, and store
     * the challenge. Returns the challenge id + OTP expiry.
     */
    public PhoneChangeStart startPhoneNumberChange(
            String userId,
            String reauthToken,
            String rawNewPhone,
            String pin,
            String passkeyAuthSessionId,
            JsonNode passkeyCredential,
            String requesterIp,
            String language) {

        // 1) Op-scoped, single-use reauth proof (confused-deputy fix). Spent here.
        try {
            reauthService.requireValidReauth(userId, reauthToken, ReauthOperation.PHONE_CHANGE);
        } catch (RuntimeException ex) {
            auditLogger.reauthFailed(userId, ReauthOperation.PHONE_CHANGE.name(), requesterIp);
            throw ex;
        }

        // 2) Non-phone step-up: PIN when the account has one, and/or passkey assertion.
        //    SIM-swap defense — the reauth OTP went to the current (possibly hijacked) number.
        enforceStepUp(userId, pin, passkeyAuthSessionId, passkeyCredential, requesterIp);

        // 3) Cooldown between successive changes.
        userSecurityService.enforcePhoneChangeCooldown(userId);

        // 4) Normalize the new number BEFORE any send/digest so it keys consistently.
        String newE164 = phoneNumberNormalizer.toE164(rawNewPhone);

        // 5) Reject equals-current before spending an OTP (no-op / pointless change).
        directoryService.findByUserId(userId).stream()
                .map(DirectoryEntry::getPhoneDigest)
                .filter(digest -> digest.equals(phoneNumberHasher.digest(newE164)))
                .findFirst()
                .ifPresent(d -> {
                    throw new PhoneAlreadyLinkedException("New number must differ from the current number");
                });

        // 6) Other-account conflict: uniform response (no enumeration oracle). We do NOT
        //    reveal here that the number is taken; the UNIQUE constraint enforces it at commit.

        String challengeId = UUID.randomUUID().toString();

        // 7) Send the challenge-namespaced OTP to the new number.
        phoneChangeOtpService.send(challengeId, newE164, requesterIp, language);

        // 8) Persist the challenge (userId|newE164|attempts=0) for the configured TTL.
        Duration ttl = properties.getSecurity().getPhoneChangeChallengeTtl();
        redisTemplate.opsForValue().set(challengeKey(challengeId), userId + "|" + newE164 + "|0", ttl);

        // 9) Audit + out-of-band alert to the OLD number (takeover visibility).
        String maskedNew = phoneNumberMasker.mask(newE164);
        String maskedOld = directoryService.findMaskedPhoneByUserId(userId).orElse(null);
        auditLogger.phoneChangeStarted(userId, maskedOld, maskedNew, requesterIp);
        deviceNotificationService.notifyPhoneChangeInitiated(userId, maskedOld, maskedNew);

        return new PhoneChangeStart(challengeId, properties.getOtp().getTtl().toSeconds());
    }

    /**
     * Step 2: validate the challenge, verify the new-number OTP under an
     * IP-independent per-challenge cap, swap the mapping atomically, then run the
     * post-commit side effects.
     */
    public void completePhoneNumberChange(String userId, String challengeId, String code, String requesterIp) {
        String key = challengeKey(challengeId);
        String stored = redisTemplate.opsForValue().get(key);
        if (!StringUtils.hasText(stored)) {
            throw new InvalidPhoneChangeChallengeException("Phone change challenge missing or expired");
        }
        String[] parts = stored.split("\\|", 3);
        if (parts.length != 3 || !parts[0].equals(userId)) {
            // Mismatched owner: destroy both the challenge and any pending OTP.
            redisTemplate.delete(key);
            phoneChangeOtpService.discard(challengeId);
            throw new InvalidPhoneChangeChallengeException("Phone change challenge does not belong to caller");
        }
        String newE164 = parts[1];
        int attempts = parseAttempts(parts[2]);

        // Verify the OTP under the per-challenge, IP-independent attempt cap.
        try {
            phoneChangeOtpService.verify(challengeId, code);
        } catch (RuntimeException ex) {
            int newAttempts = attempts + 1;
            auditLogger.phoneChangeOtpFailed(userId, newAttempts, requesterIp);
            int max = properties.getSecurity().getMaxPhoneChangeOtpAttempts();
            if (newAttempts >= max) {
                // Cap reached: burn BOTH the OTP key and the challenge so a fresh /start is required.
                redisTemplate.delete(key);
                phoneChangeOtpService.discard(challengeId);
            } else {
                // Under cap: persist the incremented counter; challenge NOT consumed.
                Long ttlSeconds = redisTemplate.getExpire(key);
                Duration ttl = (ttlSeconds != null && ttlSeconds > 0)
                        ? Duration.ofSeconds(ttlSeconds)
                        : properties.getSecurity().getPhoneChangeChallengeTtl();
                redisTemplate.opsForValue().set(key, userId + "|" + newE164 + "|" + newAttempts, ttl);
            }
            throw ex;
        }

        // OTP good. Capture the OLD homeserver-linked numbers BEFORE rebinding so we can
        // de-discover them at the federation layer afterwards (the raw old number is never
        // stored locally, only its digest/mask; the homeserver is the source of the E.164).
        List<String> oldE164ForResolver = matrixProvisioningService.getLinkedPhonesExcluding(userId, newE164);
        String oldMasked = directoryService.findMaskedPhoneByUserId(userId).orElse(null);

        // Idempotent exclusive binding on the homeserver, then the atomic swap.
        matrixProvisioningService.ensureExclusivePhoneBinding(userId, newE164);

        // Delegate to a separate bean so the @Transactional proxy engages — a same-bean
        // self-call would bypass it and the swap would NOT be atomic.
        phoneDirectorySwapService.swap(userId, newE164);

        // Challenge fully spent.
        redisTemplate.delete(key);

        String newMasked = phoneNumberMasker.mask(newE164);

        // Post-commit side effects. Each is wrapped so a failure in one never skips
        // revokeAllTokens (the real session-takeover control).
        bestEffort("resolver.registerPhone(new)", () -> resolverDirectoryClient.registerPhone(newE164));
        oldE164ForResolver.forEach(old ->
                bestEffort("resolver.unregisterPhone(old)", () -> resolverDirectoryClient.unregisterPhone(old)));
        bestEffort("revokeAllTokens", () -> tokenRevocationService.revokeAllTokens(userId));
        bestEffort("audit.phoneChangeCompleted", () -> auditLogger.phoneChangeCompleted(userId, newMasked));
        bestEffort("notify.phoneChanged", () -> deviceNotificationService.notifyPhoneChanged(userId, newMasked));

        log.info("Phone change completed for {} (old={} new={})", userId, oldMasked, newMasked);
    }

    private void enforceStepUp(String userId, String pin, String passkeyAuthSessionId, JsonNode passkeyCredential,
            String requesterIp) {
        boolean hasPin = userSecurityService.hasPin(userId);
        boolean passkeyAttempted = StringUtils.hasText(passkeyAuthSessionId) && passkeyCredential != null;
        boolean passkeyVerified = false;

        if (passkeyAttempted) {
            PasskeyService.PasskeyAuthentication assertion =
                    passkeyService.finishAuthentication(passkeyAuthSessionId, passkeyCredential);
            if (!userId.equals(assertion.userId())) {
                auditLogger.reauthFailed(userId, ReauthOperation.PHONE_CHANGE.name(), requesterIp);
                throw new InvalidPinException("Passkey does not belong to the calling account");
            }
            passkeyVerified = true;
        }

        if (hasPin) {
            try {
                userSecurityService.validatePinOrThrow(userId, pin);
            } catch (RuntimeException ex) {
                auditLogger.reauthFailed(userId, ReauthOperation.PHONE_CHANGE.name(), requesterIp);
                throw ex;
            }
            return;
        }

        if (passkeyVerified) {
            return;
        }

        // Neither a PIN nor a passkey could be asserted. Token-only fallback: residual
        // SIM-swap risk, flagged for security sign-off. We allow it so accounts without
        // either factor are not bricked out of changing their number, but it is logged.
        log.warn("Phone change for {} proceeded with reauth token only (no PIN/passkey step-up available)", userId);
    }

    private static int parseAttempts(String raw) {
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException ex) {
            return 0;
        }
    }

    private void bestEffort(String what, Runnable action) {
        try {
            action.run();
        } catch (RuntimeException ex) {
            log.warn("Post-commit phone-change step '{}' failed (continuing): {}", what, ex.getMessage());
        }
    }

    private String challengeKey(String challengeId) {
        return CHALLENGE_KEY_PREFIX + challengeId;
    }

    /** Start result: the challenge id and how long the new-number OTP is valid. */
    public record PhoneChangeStart(String challengeId, long otpExpiresInSeconds) {
    }
}
