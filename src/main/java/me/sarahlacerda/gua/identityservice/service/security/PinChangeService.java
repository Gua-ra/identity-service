package me.sarahlacerda.gua.identityservice.service.security;

import com.fasterxml.jackson.databind.JsonNode;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinOperationException;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * Starts a PIN change with the strongest factor the caller produced. Same precedence as the
 * phone-change step-up: a user-verifying passkey assertion settles it and the current PIN is not
 * consulted or charged an attempt. Without an assertion the current PIN is required. The PIN branch
 * is never removed, so a passkey that cannot be produced on this device leaves the account its PIN.
 *
 * <p>Kept out of {@link UserSecurityService} on purpose: that service must not consult passkeys
 * (see {@link AuthFactorPolicy}), and a source guard holds it to that. This class only decides
 * which factor is weighed.
 */
@Service
@RequiredArgsConstructor
public class PinChangeService {

    private final UserSecurityService userSecurityService;
    private final PasskeyService passkeyService;
    private final SecurityAuditLogger auditLogger;

    public String start(String userId, String phone, String currentPin, String passkeyStepUpId,
            JsonNode passkeyCredential, String requesterIp) {
        // An explicit JSON null arrives as a NullNode, which is not an assertion.
        boolean passkeyAttempted = StringUtils.hasText(passkeyStepUpId)
                && passkeyCredential != null && !passkeyCredential.isNull();
        if (!passkeyAttempted && !StringUtils.hasText(currentPin)) {
            // Nothing was offered: a malformed request, refused before any check and charged no attempt.
            throw new InvalidPinOperationException("The current PIN or a passkey assertion is required");
        }

        // Account checks run first, so a refusal spends neither a PIN attempt nor the ceremony.
        userSecurityService.preparePinChange(userId, phone);

        if (passkeyAttempted) {
            acceptPasskey(userId, passkeyStepUpId, passkeyCredential, requesterIp);
        } else {
            // Called across the bean boundary so it runs in its own transaction and a wrong PIN still counts
            // toward the lockout.
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
            // Enrolling a passkey needs only the bearer token, so a freshly enrolled one gets the same hold
            // the phone change applies. The caller keeps the PIN path.
            userSecurityService.enforceFreshFactorHold(assertion.credentialRegisteredAt());
        } catch (RuntimeException ex) {
            // Every refusal leaves a line, as a wrong PIN does: a ceremony that failed, a
            // credential from another account, or one too new to use.
            auditLogger.reauthFailed(userId, "PIN_CHANGE", requesterIp);
            throw ex;
        }
    }
}
