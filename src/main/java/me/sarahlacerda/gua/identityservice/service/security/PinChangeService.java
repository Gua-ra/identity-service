package me.sarahlacerda.gua.identityservice.service.security;

import com.fasterxml.jackson.databind.JsonNode;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinOperationException;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * Starts a PIN change with the strongest factor the caller produced.
 *
 * <p>
 * Same precedence as the phone-change step-up. A user-verifying passkey assertion settles it
 * and the current PIN is not consulted, so the PIN is neither demanded on top of the stronger
 * factor nor charged a failed attempt. Without an assertion the current PIN is required, as it
 * always was. There is no input for saying a passkey is unavailable, only the absence of an
 * assertion, and the PIN branch is never removed, so a credential that cannot be produced on
 * this device leaves the account its PIN.
 *
 * <p>
 * Kept out of {@link UserSecurityService} on purpose. That service owns PIN recovery, which must
 * not consult passkeys until a recovery protocol exists (see {@link AuthFactorPolicy}), and a
 * source guard holds it to that. The account checks, the PIN validation and lockout, the scoped
 * code and its audit line all stay there; this class only decides which factor is weighed.
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
        if (!passkeyAttempted && !StringUtils.hasText(currentPin)) {
            // Nothing was offered, which is a malformed request rather than a wrong PIN, so it is
            // refused before any check and charges no attempt.
            throw new InvalidPinOperationException("The current PIN or a passkey assertion is required");
        }

        // The account checks run before either factor is weighed, so a refusal for the cooldown
        // or for a number that is not the caller's spends neither a PIN attempt nor the ceremony.
        userSecurityService.preparePinChange(userId, phone);

        if (passkeyAttempted) {
            acceptPasskey(userId, passkeyStepUpId, passkeyCredential, requesterIp);
        } else {
            // Called across the bean boundary, so it runs in its own transaction and its
            // noRollbackFor holds: a wrong PIN is counted toward the lockout. Called from inside a
            // transactional method of the same class, the refusal rolled its own count back.
            userSecurityService.validatePinOrThrow(userId, currentPin);
        }
        return userSecurityService.issuePinChangeChallenge(userId, phone, requesterIp);
    }

    private void acceptPasskey(String userId, String passkeyStepUpId, JsonNode passkeyCredential,
            String requesterIp) {
        try {
            // Burned whether it is accepted or refused.
            PasskeyService.PasskeyAuthentication assertion =
                    passkeyService.finishStepUpAssertion(passkeyStepUpId, passkeyCredential);
            if (!userId.equals(assertion.userId())) {
                throw new InvalidPinException("Passkey does not belong to the calling account");
            }
            // Enrolling a passkey needs only the bearer token, so without this a session holder
            // could mint one and spend it here at once, replacing a PIN they never knew. A fresh
            // credential gets the same expiring hold the phone change applies, and the caller
            // keeps the PIN path.
            userSecurityService.enforceFreshFactorHold(assertion.credentialRegisteredAt());
        } catch (RuntimeException ex) {
            // Every refusal leaves a line, as a wrong PIN does: a ceremony that failed, a
            // credential from another account, or one too new to use.
            auditLogger.reauthFailed(userId, "PIN_CHANGE", requesterIp);
            throw ex;
        }
    }
}
