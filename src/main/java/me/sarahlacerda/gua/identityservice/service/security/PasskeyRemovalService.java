// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.security;

import com.fasterxml.jackson.databind.JsonNode;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.exception.StepUpRequiredException;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/** A bearer token alone cannot remove a credential: a passkey assertion or the PIN is required. */
@Service
public class PasskeyRemovalService {

    private final PasskeyService passkeyService;
    private final UserSecurityService userSecurityService;
    private final AuthFactorPolicy authFactorPolicy;
    private final SecurityAuditLogger auditLogger;

    public PasskeyRemovalService(PasskeyService passkeyService, UserSecurityService userSecurityService,
            AuthFactorPolicy authFactorPolicy, SecurityAuditLogger auditLogger) {
        this.passkeyService = passkeyService;
        this.userSecurityService = userSecurityService;
        this.authFactorPolicy = authFactorPolicy;
        this.auditLogger = auditLogger;
    }

    public boolean remove(String userId, String credentialId, String passkeyStepUpId, JsonNode passkeyCredential,
            String pin, String requesterIp) {
        if (!StringUtils.hasText(credentialId)) {
            throw new LoginFlowException(HttpStatus.BAD_REQUEST, "invalid_request", "No credential was named.");
        }
        // An explicit JSON null arrives as a NullNode and is not an assertion.
        boolean passkeyAttempted = StringUtils.hasText(passkeyStepUpId)
                && passkeyCredential != null && !passkeyCredential.isNull();

        if (passkeyAttempted) {
            acceptPasskey(userId, passkeyStepUpId, passkeyCredential, requesterIp);
        } else if (StringUtils.hasText(pin)) {
            // Called across the bean boundary so a wrong PIN counts toward the lockout.
            userSecurityService.validatePinOrThrow(userId, pin);
        } else {
            throw new StepUpRequiredException(
                    "Confirm it is you with your passkey or your account PIN to remove a passkey");
        }

        return passkeyService.removeCredential(userId, credentialId, authFactorPolicy.pinRegistered(userId));
    }

    private void acceptPasskey(String userId, String passkeyStepUpId, JsonNode passkeyCredential,
            String requesterIp) {
        try {
            PasskeyService.PasskeyAuthentication assertion =
                    passkeyService.finishStepUpAssertion(passkeyStepUpId, passkeyCredential);
            if (!userId.equals(assertion.userId())) {
                throw new InvalidPinException("That passkey does not belong to this account");
            }
        } catch (RuntimeException ex) {
            auditLogger.reauthFailed(userId, "PASSKEY_REMOVE", requesterIp);
            throw ex;
        }
    }
}
