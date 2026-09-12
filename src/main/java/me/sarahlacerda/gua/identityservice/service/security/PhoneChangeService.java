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
 * <p>
 * Security posture (see {@code FINAL DESIGN}):
 * <ul>
 * <li><b>/start</b> is gated by a {@code PHONE_CHANGE}-scoped, single-use reauth
 * token <em>and</em> a mandatory non-phone step-up factor. The reauth token alone
 * proves only a current-phone OTP, which a SIM-swap attacker could control, hence
 * the extra factor. Which factors count, and in which order, is
 * {@link AuthFactorPolicy#stepUpFor(ReauthOperation)}: a user-verifying passkey
 * assertion first, the account PIN as the fallback for everyone who cannot produce
 * one, and accounts that can produce neither are rejected with
 * {@code step_up_required} (403) and must set up two-step verification first;
 * there is no token-only fallback.</li>
 * <li>The new-number OTP is namespaced per challenge
 * ({@link PhoneChangeOtpService}) so the public {@code /otp/send} cannot
 * overwrite or race it.</li>
 * <li>A passkey offered as the step-up factor must come from the dedicated,
 * user-verifying step-up ceremony ({@code POST /security/passkey/stepup/options}).
 * A possession-only assertion is refused: it would stand in for a factor that
 * counts failures and locks out, while carrying neither.</li>
 * <li>A PIN that was just created, changed or reset is refused as the step-up
 * factor until the fresh-2FA hold elapses, because the permissive login side can
 * mint a PIN and that PIN would otherwise re-point the number immediately. This
 * is an ADDITIONAL refusal; the per-account change cooldown and the reset
 * dormancy gates are untouched and still run.</li>
 * <li>{@code /complete} enforces an IP-independent per-challenge wrong-OTP cap,
 * then performs one atomic directory swap that carries
 * displayName/discoverable/username/homeserverId forward, then post-commit
 * revokes all tokens, audits and notifies.</li>
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

        // 1) Op-scoped, single-use reauth proof (confused-deputy fix). Spent here.
        try {
            reauthService.requireValidReauth(userId, reauthToken, ReauthOperation.PHONE_CHANGE);
        } catch (RuntimeException ex) {
            auditLogger.reauthFailed(userId, ReauthOperation.PHONE_CHANGE.name(), requesterIp);
            throw ex;
        }

        // 2) Non-phone step-up: a user-verifying passkey assertion, else the account PIN.
        //    SIM-swap defense, since the reauth OTP went to the current (possibly hijacked)
        //    number. Accounts with neither factor are hard-blocked (step_up_required).
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

        // OTP good.
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
        bestEffort("revokeAllTokens", () -> tokenRevocationService.revokeAllTokens(userId));
        bestEffort("audit.phoneChangeCompleted", () -> auditLogger.phoneChangeCompleted(userId, newMasked));
        bestEffort("notify.phoneChanged", () -> deviceNotificationService.notifyPhoneChanged(userId, newMasked));

        log.info("Phone change completed for {} (old={} new={})", userId, oldMasked, newMasked);
    }

    private void enforceStepUp(String userId, String pin, String passkeyStepUpId, JsonNode passkeyCredential,
            String requesterIp) {
        // Which factors this operation accepts, and in which order, is
        // AuthFactorPolicy.stepUpFor(PHONE_CHANGE): [PASSKEY, PIN], hard block when neither
        // can be produced. The branches below are that list, in that order. Whether THIS
        // account holds a PIN comes from the same component, so login, this step-up and
        // recovery all read one answer instead of three.
        //
        // The policy is consulted for those facts and is deliberately NOT wired as a
        // condition on the branches themselves. A policy value that could switch the PIN
        // branch off, or switch the refusal at the bottom off, would be a lever that turns a
        // configuration edit into either account lockout or a bypass. Precedence is pinned by
        // tests against stepUpFor(PHONE_CHANGE) instead.
        boolean hasPin = authFactorPolicy.pinRegistered(userId);
        boolean passkeyAttempted = StringUtils.hasText(passkeyStepUpId) && passkeyCredential != null;

        // Strongest factor first. A user-verifying assertion settles the step-up on its own:
        // it is the preferred factor, and demanding the PIN as well from someone who just
        // proved a passkey would make the stronger factor worth less than the weaker one.
        if (passkeyAttempted) {
            // A step-up assertion, not a login assertion: the ceremony demanded user
            // verification and PasskeyService refuses a response that did not do it. The
            // challenge is burned whether this succeeds or fails, so a refused attempt cannot
            // be retried against the same challenge.
            PasskeyService.PasskeyAuthentication assertion =
                    passkeyService.finishStepUpAssertion(passkeyStepUpId, passkeyCredential);
            // Ownership first. Nothing below may treat the assertion as accepted until the
            // credential is known to belong to the account making the call.
            if (!userId.equals(assertion.userId())) {
                auditLogger.reauthFailed(userId, ReauthOperation.PHONE_CHANGE.name(), requesterIp);
                throw new InvalidPinException("Passkey does not belong to the calling account");
            }
            // Accepted. The fresh-2FA hold is NOT applied here and must not be: it exists to
            // stop a PIN minted minutes ago by a session from re-pointing the number, and this
            // caller did not spend a PIN. Holding the stronger factor for the weaker one's
            // reason would refuse people who did nothing the hold is about.
            return;
        }

        // Demoted below the passkey, never removed. An account with a PIN and no passkey, or
        // one whose passkey cannot be produced on this device, still comes through here, and
        // this branch is the only reason an unusable credential is not an unusable account.
        if (hasPin) {
            try {
                userSecurityService.validatePinOrThrow(userId, pin);
            } catch (RuntimeException ex) {
                auditLogger.reauthFailed(userId, ReauthOperation.PHONE_CHANGE.name(), requesterIp);
                throw ex;
            }
            // The PIN is the factor being accepted here, so the fresh-2FA hold applies to it.
            // Deliberately inside this branch and after the check that accepts the PIN: an
            // account that proved a passkey returned above and is never held for a fresh PIN
            // it did not use.
            userSecurityService.enforcePhoneChangePinHold(userId);
            return;
        }

        // Neither a PIN nor a passkey could be asserted. Hard block (product decision,
        // 2026-07-02): the reauth token alone only proves a current-phone OTP, which a
        // SIM-swap attacker may control, so there is NO token-only fallback. Unconditional,
        // because a refusal that any single edit can turn into a fallthrough is not a
        // refusal. The client routes `step_up_required` to two-step verification setup.
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
