package me.sarahlacerda.gua.identityservice.service.security;

import com.fasterxml.jackson.databind.JsonNode;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinOperationException;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

// A user-verifying passkey assertion authorizes the change without the current PIN. Otherwise the current PIN
// is required.
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
            PasskeyService.PasskeyAuthentication assertion =
                    passkeyService.finishStepUpAssertion(passkeyStepUpId, passkeyCredential);
            if (!userId.equals(assertion.userId())) {
                throw new InvalidPinException("Passkey does not belong to the calling account");
            }
            // A freshly enrolled passkey gets the same hold as on a phone change.
            userSecurityService.enforceFreshFactorHold(assertion.credentialRegisteredAt());
        } catch (RuntimeException ex) {
            auditLogger.reauthFailed(userId, "PIN_CHANGE", requesterIp);
            throw ex;
        }
    }
}
