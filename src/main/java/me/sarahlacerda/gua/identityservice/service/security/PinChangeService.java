package me.sarahlacerda.gua.identityservice.service.security;

import com.fasterxml.jackson.databind.JsonNode;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * Starts a PIN change with the strongest factor the caller produced.
 *
 * <p>
 * Same precedence as the phone-change step-up. A user-verifying passkey assertion settles it
 * and the current PIN is not consulted, so the PIN is neither demanded on top of the stronger
 * factor nor charged a failed attempt. Without an assertion the start is exactly the one every
 * PIN holder had before, in {@link UserSecurityService#startPinChange}. There is no input for
 * saying a passkey is unavailable, only the absence of an assertion, and the PIN branch is
 * never removed, so a credential that cannot be produced on this device leaves the account its
 * PIN.
 *
 * <p>
 * Kept out of {@link UserSecurityService} on purpose. That service owns PIN recovery, which must
 * not consult passkeys until a recovery protocol exists (see {@link AuthFactorPolicy}), and a
 * source guard holds it to that. Whatever this class decides, the account checks, the scoped
 * code and the audit line come from the same two methods the PIN start uses.
 */
@Service
@RequiredArgsConstructor
public class PinChangeService {

    private final UserSecurityService userSecurityService;
    private final PasskeyService passkeyService;
    private final SecurityAuditLogger auditLogger;

    public String start(String userId, String phone, String currentPin, String passkeyStepUpId,
            JsonNode passkeyCredential, String requesterIp) {
        // An explicit JSON null arrives as a NullNode, which is no more an assertion than a
        // missing field.
        boolean passkeyAttempted = StringUtils.hasText(passkeyStepUpId)
                && passkeyCredential != null && !passkeyCredential.isNull();
        if (!passkeyAttempted) {
            return userSecurityService.startPinChange(userId, phone, currentPin, requesterIp);
        }

        // The account checks run before the ceremony is spent, so a refusal for the cooldown or
        // for a number that is not the caller's leaves the challenge unburned.
        userSecurityService.preparePinChange(userId, phone);

        // Burned whether it is accepted or refused.
        PasskeyService.PasskeyAuthentication assertion =
                passkeyService.finishStepUpAssertion(passkeyStepUpId, passkeyCredential);
        if (!userId.equals(assertion.userId())) {
            auditLogger.reauthFailed(userId, "PIN_CHANGE", requesterIp);
            throw new InvalidPinException("Passkey does not belong to the calling account");
        }
        // Enrolling a passkey needs only the bearer token, so without this a session holder
        // could mint one and spend it here at once, replacing a PIN they never knew. A fresh
        // credential gets the same expiring hold the phone change applies, and the caller keeps
        // the PIN path.
        userSecurityService.enforceFreshFactorHold(assertion.credentialRegisteredAt());
        return userSecurityService.issuePinChangeChallenge(userId, phone, requesterIp);
    }
}
