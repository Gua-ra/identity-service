// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Instant;

import com.fasterxml.jackson.databind.JsonNode;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityPolicy.StepUpPolicy;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * Accepts the step-up an authority transition is scoped to (ADM-009 decision 4 step 2).
 *
 * <p>Same precedence as the phone change and the PIN change: a user-verifying passkey assertion settles it
 * and the PIN is not consulted, so the PIN is neither demanded on top of the stronger factor nor charged a
 * failed attempt. Without an assertion the account PIN is required. There is no input for saying a passkey is
 * unavailable, only the absence of an assertion, and the PIN branch is never removed, so a credential that
 * cannot be produced on this device leaves the account its PIN.
 *
 * <p>Two things make this a different step-up from the ones that already exist rather than a reuse of them:
 *
 * <ul>
 * <li><b>It is scoped by the challenge it mints, not by a token.</b> A step-up performed for a phone change
 * or a PIN change does not carry over, because O9 asks for a possession proof of <em>this</em> transition.
 * The scope is enforced by minting the challenge in the same call: there is no step-up artifact that outlives
 * the challenge, so "a step-up no older than the challenge" holds by construction.</li>
 * <li><b>The phone is not in it.</b> {@code ReauthTokenService} and {@code AccountReauthService} are the
 * existing operation-scoped proofs, and both are minted by an SMS code. Reusing them would put phone
 * possession at the root of an authority transition, which is the whole lesson of the design ADM-008
 * rejected. This service references neither, and a guard test fails the build if it ever does.</li>
 * </ul>
 *
 * <p>The fresh-factor hold is applied by {@link AuthorityPolicy}, on the instant this returns, after the
 * factor is known to be the caller's own. Weighing an age before ownership would tell a caller something
 * about a credential that is not theirs.
 */
@Service
public class AuthorityStepUpService {

    private final PasskeyService passkeyService;
    private final UserSecurityService userSecurityService;
    private final AuthorityPolicy policy;
    private final SecurityAuditLogger auditLogger;

    public AuthorityStepUpService(PasskeyService passkeyService, UserSecurityService userSecurityService,
            AuthorityPolicy policy, SecurityAuditLogger auditLogger) {
        this.passkeyService = passkeyService;
        this.userSecurityService = userSecurityService;
        this.policy = policy;
        this.auditLogger = auditLogger;
    }

    /**
     * Accepts the strongest proof the caller produced, and refuses when the policy hard-blocks and none was.
     *
     * @param operation what the step-up is for, for the audit line only
     * @return which factor settled it and when that credential came into being, or an empty acceptance when
     *         the purpose asks for no factor at all
     */
    public Accepted accept(String userId, StepUpPolicy stepUp, String operation, String passkeyStepUpId,
            JsonNode passkeyCredential, String pin, String requesterIp) {
        if (!stepUp.required()) {
            // Only the browser-started approval reaches this, and it grants nothing on its own.
            return new Accepted(null, null);
        }

        // An explicit JSON null arrives as a NullNode, which is no more an assertion than a missing field.
        boolean passkeyAttempted = StringUtils.hasText(passkeyStepUpId)
                && passkeyCredential != null && !passkeyCredential.isNull();

        if (passkeyAttempted && stepUp.accepts(AuthFactor.PASSKEY)) {
            return acceptPasskey(userId, passkeyStepUpId, passkeyCredential, operation, requesterIp);
        }
        if (StringUtils.hasText(pin) && stepUp.accepts(AuthFactor.PIN)) {
            return acceptPin(userId, pin, operation, requesterIp);
        }

        // Unconditional, because a refusal that any single edit can turn into a fallthrough is not a
        // refusal. There is no third branch to reach, and in particular no code sent to the number.
        throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_step_up_required",
                "Confirm it is you with your passkey or your account PIN first.");
    }

    private Accepted acceptPasskey(String userId, String passkeyStepUpId, JsonNode passkeyCredential,
            String operation, String requesterIp) {
        try {
            // Burned whether it is accepted or refused, in the ceremony's own finally.
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
            // Across the bean boundary, so its own transaction and its noRollbackFor hold and a wrong PIN
            // counts toward the lockout.
            userSecurityService.validatePinOrThrow(userId, pin);
        } catch (RuntimeException ex) {
            auditLogger.reauthFailed(userId, operation, requesterIp);
            throw ex;
        }
        return new Accepted(AuthFactor.PIN, userSecurityService.pinSetAt(userId).orElse(null));
    }

    /**
     * Applies the hold rules a transition owes before it may start (ADM-009 decision 4 step 2 and decision 9
     * rule 3). Both refusals expire on their own and take nothing away from anyone.
     *
     * <p>Not applied to an opposition. The hold gates starting a transition and never opposing one: an owner
     * who has just changed their PIN to lock a thief out must not be the one disarmed by it.
     */
    public void enforceHolds(String userId, Accepted accepted) {
        if (accepted.factor() != null) {
            policy.enforceFreshFactorHold(accepted.factorCreatedAt());
        }
        policy.enforceRecoveryOutsideHold(userId);
    }

    /**
     * What settled the step-up.
     *
     * @param factor          the factor presented, or null when the purpose asked for none
     * @param factorCreatedAt when that credential came into being, which is what the hold weighs
     */
    public record Accepted(AuthFactor factor, Instant factorCreatedAt) {
    }
}
