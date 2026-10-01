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

    public PhoneChangeStart startPhoneNumberChange(
            String userId,
            String reauthToken,
            String rawNewPhone,
            String pin,
            String passkeyStepUpId,
            JsonNode passkeyCredential,
            String requesterIp,
            String language) {

        try {
            reauthService.requireValidReauth(userId, reauthToken, ReauthOperation.PHONE_CHANGE);
        } catch (RuntimeException ex) {
            auditLogger.reauthFailed(userId, ReauthOperation.PHONE_CHANGE.name(), requesterIp);
            throw ex;
        }

        enforceStepUp(userId, pin, passkeyStepUpId, passkeyCredential, requesterIp);

        userSecurityService.enforcePhoneChangeCooldown(userId);

        String newE164 = phoneNumberNormalizer.toE164(rawNewPhone);

        directoryService.findByUserId(userId).stream()
                .map(DirectoryEntry::getPhoneDigest)
                .filter(digest -> digest.equals(phoneNumberHasher.digest(newE164)))
                .findFirst()
                .ifPresent(d -> {
                    throw new PhoneAlreadyLinkedException("New number must differ from the current number");
                });

        // A number owned by another account is not revealed here. The UNIQUE constraint enforces it at commit.

        String challengeId = UUID.randomUUID().toString();

        phoneChangeOtpService.send(challengeId, newE164, requesterIp, language);

        Duration ttl = properties.getSecurity().getPhoneChangeChallengeTtl();
        redisTemplate.opsForValue().set(challengeKey(challengeId), userId + "|" + newE164 + "|0", ttl);

        String maskedNew = phoneNumberMasker.mask(newE164);
        String maskedOld = directoryService.findMaskedPhoneByUserId(userId).orElse(null);
        auditLogger.phoneChangeStarted(userId, maskedOld, maskedNew, requesterIp);
        deviceNotificationService.notifyPhoneChangeInitiated(userId, maskedOld, maskedNew);

        return new PhoneChangeStart(challengeId, properties.getOtp().getTtl().toSeconds());
    }

    public void completePhoneNumberChange(String userId, String challengeId, String code, String requesterIp) {
        String key = challengeKey(challengeId);
        String stored = redisTemplate.opsForValue().get(key);
        if (!StringUtils.hasText(stored)) {
            throw new InvalidPhoneChangeChallengeException("Phone change challenge missing or expired");
        }
        String[] parts = stored.split("\\|", 3);
        if (parts.length != 3 || !parts[0].equals(userId)) {
            redisTemplate.delete(key);
            phoneChangeOtpService.discard(challengeId);
            throw new InvalidPhoneChangeChallengeException("Phone change challenge does not belong to caller");
        }
        String newE164 = parts[1];
        int attempts = parseAttempts(parts[2]);

        try {
            phoneChangeOtpService.verify(challengeId, code);
        } catch (RuntimeException ex) {
            int newAttempts = attempts + 1;
            auditLogger.phoneChangeOtpFailed(userId, newAttempts, requesterIp);
            int max = properties.getSecurity().getMaxPhoneChangeOtpAttempts();
            if (newAttempts >= max) {
                redisTemplate.delete(key);
                phoneChangeOtpService.discard(challengeId);
            } else {
                Long ttlSeconds = redisTemplate.getExpire(key);
                Duration ttl = (ttlSeconds != null && ttlSeconds > 0)
                        ? Duration.ofSeconds(ttlSeconds)
                        : properties.getSecurity().getPhoneChangeChallengeTtl();
                redisTemplate.opsForValue().set(key, userId + "|" + newE164 + "|" + newAttempts, ttl);
            }
            throw ex;
        }

        String oldMasked = directoryService.findMaskedPhoneByUserId(userId).orElse(null);

        matrixProvisioningService.ensureExclusivePhoneBinding(userId, newE164);

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

        if (passkeyAttempted) {
            // The challenge is burned whether this succeeds or fails.
            PasskeyService.PasskeyAuthentication assertion =
                    passkeyService.finishStepUpAssertion(passkeyStepUpId, passkeyCredential);
            if (!userId.equals(assertion.userId())) {
                auditLogger.reauthFailed(userId, ReauthOperation.PHONE_CHANGE.name(), requesterIp);
                throw new InvalidPinException("Passkey does not belong to the calling account");
            }
            // The hold is checked against the credential that answered, not the account.
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
            // The hold applies only when the PIN is the factor accepted.
            userSecurityService.enforcePhoneChangePinHold(userId);
            return;
        }

        // Hard block: no token-only fallback. The client routes step_up_required to two-step verification
        // setup.
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

    public record PhoneChangeStart(String challengeId, long otpExpiresInSeconds) {
    }
}
