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

/**
 * Removes one passkey credential, behind the same step-up the other privileged operations use.
 *
 * <p>The capability is a prerequisite of ADM-009 (gate 5) rather than a convenience. Until now the only way to
 * remove a credential was to remove them all, so an owner locking a thief out of a stolen device had to wipe
 * every credential and register a new one, which put their own remaining factor inside the fresh-factor hold.
 * The hold is a week on a phone change and, once the authority chain is on, on rooting or moving an account, so
 * the tool for locking a thief out was also the tool that disarmed the owner.
 *
 * <p>Same precedence as the phone change and the PIN change: a user-verifying passkey assertion settles it and
 * the PIN is not consulted, otherwise the PIN is required, and there is no third way through. Removing a
 * credential is a change to what the account can produce, so a bearer token on its own is not enough: that
 * token is what an attacker gets hold of, and stripping the owner's factors is a step toward taking the
 * account, not away from it.
 *
 * <p>Kept out of {@link PasskeyService} on purpose, in the shape {@link PinChangeService} established: the
 * ceremony and the storage live there, and which factor is weighed lives here.
 */
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

    /**
     * Removes the named credential after a step-up.
     *
     * @return whether a credential of this account with that id existed
     * @throws LoginFlowException 409 {@code factor_required} when it is the account's last factor
     */
    public boolean remove(String userId, String credentialId, String passkeyStepUpId, JsonNode passkeyCredential,
            String pin, String requesterIp) {
        if (!StringUtils.hasText(credentialId)) {
            throw new LoginFlowException(HttpStatus.BAD_REQUEST, "invalid_request", "No credential was named.");
        }
        // An explicit JSON null arrives as a NullNode, which is no more an assertion than a missing field.
        boolean passkeyAttempted = StringUtils.hasText(passkeyStepUpId)
                && passkeyCredential != null && !passkeyCredential.isNull();

        if (passkeyAttempted) {
            acceptPasskey(userId, passkeyStepUpId, passkeyCredential, requesterIp);
        } else if (StringUtils.hasText(pin)) {
            // Across the bean boundary, so a wrong PIN counts toward the lockout.
            userSecurityService.validatePinOrThrow(userId, pin);
        } else {
            throw new StepUpRequiredException(
                    "Confirm it is you with your passkey or your account PIN to remove a passkey");
        }

        // The account keeps a way in either way: a PIN it still holds means removing the last credential is not
        // removing the last factor.
        return passkeyService.removeCredential(userId, credentialId, authFactorPolicy.pinRegistered(userId));
    }

    private void acceptPasskey(String userId, String passkeyStepUpId, JsonNode passkeyCredential,
            String requesterIp) {
        try {
            // Burned whether it is accepted or refused.
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
