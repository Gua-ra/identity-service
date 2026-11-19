package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Duration;
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
import me.sarahlacerda.gua.identityservice.exception.StepUpRequiredException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.MatrixProvisioningService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberMasker;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberNormalizer;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * Two-step orchestration for changing an account's verified phone number.
 *
 * <ul>
 * <li><b>/start</b> is gated by a {@code PHONE_CHANGE}-scoped, single-use reauth token and a
 * mandatory non-phone step-up factor (see {@link AuthFactorPolicy#stepUpFor(ReauthOperation)}): a
 * user-verifying passkey assertion first, the account PIN as the fallback. An account that can
 * produce neither is rejected with {@code step_up_required} (403); there is no token-only fallback.</li>
 * <li>The new-number OTP is namespaced per challenge ({@link PhoneChangeOtpService}), so the public
 * {@code /otp/send} cannot overwrite or race it.</li>
 * <li>A passkey offered as the step-up must come from the user-verifying step-up ceremony
 * ({@code POST /security/passkey/stepup/options}). A possession-only assertion is refused.</li>
 * <li>A PIN or passkey that was just created is refused as the step-up factor until the fresh-2FA
 * hold elapses. This is in addition to the per-account change cooldown.</li>
 * <li>{@code /complete} enforces an IP-independent per-challenge wrong-OTP cap, then performs one
 * atomic directory swap that carries displayName, discoverable, username and homeserverId forward,
 * then post-commit revokes all tokens, audits and notifies.</li>
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
    private final AuthFactorPolicy authFactorPolicy;
    private final PasskeyService passkeyService;
    private final PhoneChangeOtpService phoneChangeOtpService;
    private final PhoneNumberNormalizer phoneNumberNormalizer;
    private final PhoneNumberHasher phoneNumberHasher;
    private final PhoneNumberMasker phoneNumberMasker;
    private final DirectoryService directoryService;
    private final PhoneDirectorySwapService phoneDirectorySwapService;
    private final MatrixProvisioningService matrixProvisioningService;
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
            String passkeyStepUpId,
            JsonNode passkeyCredential,
            String requesterIp,
            String language) {

        // 1) Operation-scoped, single-use reauth proof. Spent here.
        try {
            reauthService.requireValidReauth(userId, reauthToken, ReauthOperation.PHONE_CHANGE);
        } catch (RuntimeException ex) {
            auditLogger.reauthFailed(userId, ReauthOperation.PHONE_CHANGE.name(), requesterIp);
            throw ex;
        }

        // 2) Non-phone step-up: a user-verifying passkey assertion, else the account PIN. The reauth OTP
        //    went to the current (possibly hijacked) number. Accounts with neither factor are hard-blocked.
        enforceStepUp(userId, pin, passkeyStepUpId, passkeyCredential, requesterIp);

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

        // 6) A number owned by another account is not revealed here. The UNIQUE constraint enforces it at commit.

        String challengeId = UUID.randomUUID().toString();

        // 7) Send the challenge-namespaced OTP to the new number.
        phoneChangeOtpService.send(challengeId, newE164, requesterIp, language);

        // 8) Persist the challenge (userId|newE164|attempts=0) for the configured TTL.
        Duration ttl = properties.getSecurity().getPhoneChangeChallengeTtl();
        redisTemplate.opsForValue().set(challengeKey(challengeId), userId + "|" + newE164 + "|0", ttl);

        // 9) Audit and out-of-band alert to the old number.
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

        String oldMasked = directoryService.findMaskedPhoneByUserId(userId).orElse(null);

        // Idempotent exclusive binding on the homeserver, then the atomic swap.
        matrixProvisioningService.ensureExclusivePhoneBinding(userId, newE164);

        // Delegate to a separate bean so the @Transactional proxy engages. A same-bean self-call would
        // bypass it and the swap would not be atomic.
        phoneDirectorySwapService.swap(userId, newE164);

        redisTemplate.delete(key);

        String newMasked = phoneNumberMasker.mask(newE164);

        // Each side effect is wrapped so a failure never skips revokeAllTokens.
        bestEffort("revokeAllTokens", () -> tokenRevocationService.revokeAllTokens(userId));
        bestEffort("audit.phoneChangeCompleted", () -> auditLogger.phoneChangeCompleted(userId, newMasked));
        bestEffort("notify.phoneChanged", () -> deviceNotificationService.notifyPhoneChanged(userId, newMasked));

        log.info("Phone change completed for {} (old={} new={})", userId, oldMasked, newMasked);
    }

    private void enforceStepUp(String userId, String pin, String passkeyStepUpId, JsonNode passkeyCredential,
            String requesterIp) {
        // The branches follow AuthFactorPolicy.stepUpFor(PHONE_CHANGE) but are deliberately not driven by it:
        // a policy value must not be able to switch a branch off.
        boolean hasPin = authFactorPolicy.pinRegistered(userId);
        boolean passkeyAttempted = StringUtils.hasText(passkeyStepUpId) && passkeyCredential != null;

        // Strongest factor first. A user-verifying assertion settles the step-up on its own.
        if (passkeyAttempted) {
            // A step-up assertion, not a login assertion: PasskeyService refuses a response without user
            // verification. The challenge is burned whether this succeeds or fails.
            PasskeyService.PasskeyAuthentication assertion =
                    passkeyService.finishStepUpAssertion(passkeyStepUpId, passkeyCredential);
            // Ownership first. Nothing below may treat the assertion as accepted until the
            // credential is known to belong to the account making the call.
            if (!userId.equals(assertion.userId())) {
                auditLogger.reauthFailed(userId, ReauthOperation.PHONE_CHANGE.name(), requesterIp);
                throw new InvalidPinException("Passkey does not belong to the calling account");
            }
            // A freshly enrolled passkey is held like a freshly set PIN, on the same window. The hold is
            // checked against the credential that answered, not the account, and a refused caller can retry
            // with the PIN.
            userSecurityService.enforceFreshFactorHold(assertion.credentialRegisteredAt());
            return;
        }

        // The PIN branch must stay: it is the way through for an account whose passkey cannot be produced.
        if (hasPin) {
            try {
                userSecurityService.validatePinOrThrow(userId, pin);
            } catch (RuntimeException ex) {
                auditLogger.reauthFailed(userId, ReauthOperation.PHONE_CHANGE.name(), requesterIp);
                throw ex;
            }
            // The hold applies only when the PIN is the factor accepted: an account that proved a passkey
            // returned above.
            userSecurityService.enforcePhoneChangePinHold(userId);
            return;
        }

        // Neither a PIN nor a passkey could be asserted. Hard block: the reauth token alone only proves
        // a current-phone OTP, so there is no token-only fallback. The client routes step_up_required to
        // two-step verification setup.
        auditLogger.reauthFailed(userId, ReauthOperation.PHONE_CHANGE.name(), requesterIp);
        throw new StepUpRequiredException(
                "Two-step verification (account PIN or passkey) is required to change the phone number");
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
