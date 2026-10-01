// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Instant;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityPolicy.StepUpPolicy;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityWebStepUpService.Proved;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * A passkey assertion settles the step-up and the PIN is then not consulted. Must never reference the
 * SMS-backed reauth services (AccountAuthorityGuardTest).
 */
@Service
public class AuthorityStepUpService {

    private final PasskeyService passkeyService;
    private final UserSecurityService userSecurityService;
    private final AuthorityPolicy policy;
    private final AuthorityWebStepUpService webStepUps;
    private final SecurityAuditLogger auditLogger;

    public AuthorityStepUpService(PasskeyService passkeyService, UserSecurityService userSecurityService,
            AuthorityPolicy policy, AuthorityWebStepUpService webStepUps, SecurityAuditLogger auditLogger) {
        this.passkeyService = passkeyService;
        this.userSecurityService = userSecurityService;
        this.policy = policy;
        this.webStepUps = webStepUps;
        this.auditLogger = auditLogger;
    }

    /** Order: a passkey in this request, then the PIN in this request, then a proof left by the web sheet. */
    public Accepted accept(String userId, Purpose purpose, String sessionHash, StepUpPolicy stepUp,
            String passkeyStepUpId, JsonNode passkeyCredential, String pin, String requesterIp) {
        String operation = "AUTHORITY_" + purpose;
        if (stepUp.required() && !presentedSomething(passkeyStepUpId, passkeyCredential, pin)) {
            Optional<Proved> fromSheet = webStepUps.consume(userId, sessionHash, purpose);
            if (fromSheet.isPresent()) {
                Proved proved = fromSheet.get();
                if (!stepUp.accepts(proved.factor())) {
                    throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_step_up_required",
                            "Confirm it is you with your passkey or your account PIN first.");
                }
                return new Accepted(proved.factor(), proved.factorCreatedAt());
            }
        }
        return accept(userId, stepUp, operation, passkeyStepUpId, passkeyCredential, pin, requesterIp);
    }

    public Accepted accept(String userId, StepUpPolicy stepUp, String operation, String passkeyStepUpId,
            JsonNode passkeyCredential, String pin, String requesterIp) {
        if (!stepUp.required()) {
            return new Accepted(null, null);
        }

        boolean passkeyAttempted = assertionOffered(passkeyStepUpId, passkeyCredential);

        if (passkeyAttempted && stepUp.accepts(AuthFactor.PASSKEY)) {
            return acceptPasskey(userId, passkeyStepUpId, passkeyCredential, operation, requesterIp);
        }
        if (StringUtils.hasText(pin) && stepUp.accepts(AuthFactor.PIN)) {
            return acceptPin(userId, pin, operation, requesterIp);
        }

        throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_step_up_required",
                "Confirm it is you with your passkey or your account PIN first.");
    }

    /** An explicit JSON null arrives as a NullNode and is not an assertion. */
    private static boolean assertionOffered(String passkeyStepUpId, JsonNode passkeyCredential) {
        return StringUtils.hasText(passkeyStepUpId) && passkeyCredential != null && !passkeyCredential.isNull();
    }

    private static boolean presentedSomething(String passkeyStepUpId, JsonNode passkeyCredential, String pin) {
        return assertionOffered(passkeyStepUpId, passkeyCredential) || StringUtils.hasText(pin);
    }

    private Accepted acceptPasskey(String userId, String passkeyStepUpId, JsonNode passkeyCredential,
            String operation, String requesterIp) {
        try {
            PasskeyService.PasskeyAuthentication assertion =
                    passkeyService.finishStepUpAssertion(passkeyStepUpId, passkeyCredential);
            if (!userId.equals(assertion.userId())) {
                throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_step_up_required",
                        "That passkey does not belong to this account.");
            }
            return new Accepted(AuthFactor.PASSKEY, assertion.credentialRegisteredAt());
        } catch (RuntimeException ex) {
            auditLogger.reauthFailed(userId, operation, requesterIp);
            throw ex;
        }
    }

    private Accepted acceptPin(String userId, String pin, String operation, String requesterIp) {
        try {
            userSecurityService.validatePinOrThrow(userId, pin);
        } catch (RuntimeException ex) {
            auditLogger.reauthFailed(userId, operation, requesterIp);
            throw ex;
        }
        return new Accepted(AuthFactor.PIN, userSecurityService.pinSetAt(userId).orElse(null));
    }

    /** Holds gate starting a transition, never an opposition or a notification registration. */
    public void enforceHolds(String userId, Purpose purpose, Accepted accepted) {
        if (purpose == Purpose.OPPOSE || purpose == Purpose.NOTIFY) {
            return;
        }
        if (accepted.factor() != null) {
            policy.enforceFreshFactorHold(accepted.factorCreatedAt());
        }
        policy.enforceRecoveryOutsideHold(userId);
    }

    public record Accepted(AuthFactor factor, Instant factorCreatedAt) {
    }
}
