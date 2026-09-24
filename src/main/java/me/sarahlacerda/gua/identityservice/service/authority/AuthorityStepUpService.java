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
 *
 * <p>There is a third way to take this step-up and it is not a third factor: the web sheet of
 * {@link AuthorityWebStepUpService}, where the same passkey assertion or the same PIN is run on a page this
 * service serves, for a platform that cannot run the assertion natively. It is weighed by the purpose-scoped
 * overload of {@link #accept}, only for a request that produced no proof of its own, and only from a row this
 * service wrote about a ceremony it ran.
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

    /**
     * The same step-up, with the web sheet counted as a way of taking it (ADM-009 decision 4 step 2).
     *
     * <p>Order, and it is the only order that keeps the native path untouched: a passkey assertion in this
     * request settles it, then the PIN in this request, and only a request that produced neither looks for a
     * proof the sheet left behind for this account, this session and this purpose. A client that signs its own
     * assertions never reaches the third branch, so nothing about the existing platforms changes.
     *
     * <p>The sheet is not a weaker proof and not a third factor. It is the same two factors, run where they
     * can be run, on a page this service serves, and recorded by this service rather than claimed by a client.
     * What the caller hands back is nothing at all: there is no token in this signature for a sheet, because a
     * token a client carries is a token a client can be talked out of.
     */
    public Accepted accept(String userId, Purpose purpose, String sessionHash, StepUpPolicy stepUp,
            String passkeyStepUpId, JsonNode passkeyCredential, String pin, String requesterIp) {
        String operation = "AUTHORITY_" + purpose;
        if (stepUp.required() && !presentedSomething(passkeyStepUpId, passkeyCredential, pin)) {
            Optional<Proved> fromSheet = webStepUps.consume(userId, sessionHash, purpose);
            if (fromSheet.isPresent()) {
                Proved proved = fromSheet.get();
                if (!stepUp.accepts(proved.factor())) {
                    // The sheet only ever records the passkey or the PIN, and every purpose that opens one
                    // accepts both. Refused rather than ignored, because the alternative to a refusal here is
                    // falling through to a branch that would report "no proof was produced" about a proof
                    // that was.
                    throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_step_up_required",
                            "Confirm it is you with your passkey or your account PIN first.");
                }
                return new Accepted(proved.factor(), proved.factorCreatedAt());
            }
        }
        return accept(userId, stepUp, operation, passkeyStepUpId, passkeyCredential, pin, requesterIp);
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

        boolean passkeyAttempted = assertionOffered(passkeyStepUpId, passkeyCredential);

        if (passkeyAttempted && stepUp.accepts(AuthFactor.PASSKEY)) {
            return acceptPasskey(userId, passkeyStepUpId, passkeyCredential, operation, requesterIp);
        }
        if (StringUtils.hasText(pin) && stepUp.accepts(AuthFactor.PIN)) {
            return acceptPin(userId, pin, operation, requesterIp);
        }

        // Unconditional, because a refusal that any single edit can turn into a fallthrough is not a
        // refusal. There is no third branch here, and in particular no code sent to the number. The one
        // other way to satisfy this step-up is the web sheet, and it is weighed by the overload above,
        // before this method is reached, on a proof this service recorded rather than one a caller sent.
        throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_step_up_required",
                "Confirm it is you with your passkey or your account PIN first.");
    }

    /** An explicit JSON null arrives as a NullNode, which is no more an assertion than a missing field. */
    private static boolean assertionOffered(String passkeyStepUpId, JsonNode passkeyCredential) {
        return StringUtils.hasText(passkeyStepUpId) && passkeyCredential != null && !passkeyCredential.isNull();
    }

    /**
     * Whether this request carried a proof of its own, which is what decides whether the sheet is looked at.
     *
     * <p>Deliberately not "whether the caller says it can produce one": there is no input for that claim
     * anywhere in this service, because a claim that a factor is unavailable costs an attacker nothing.
     */
    private static boolean presentedSomething(String passkeyStepUpId, JsonNode passkeyCredential, String pin) {
        return assertionOffered(passkeyStepUpId, passkeyCredential) || StringUtils.hasText(pin);
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
     * <p>Not applied to an opposition, and not to a notification registration. The hold gates starting a
     * transition and never opposing one: an owner who has just changed their PIN to lock a thief out must not
     * be the one disarmed by it, and an owner who has just been through a legitimate recovery must not be
     * refused the very channel the next window will be announced on. Neither purpose grants authority, so
     * neither is the laundering path decision 9 rule 3 closes.
     */
    public void enforceHolds(String userId, Purpose purpose, Accepted accepted) {
        if (purpose == Purpose.OPPOSE || purpose == Purpose.NOTIFY) {
            return;
        }
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
