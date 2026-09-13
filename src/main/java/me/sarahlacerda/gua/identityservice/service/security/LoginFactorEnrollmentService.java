package me.sarahlacerda.gua.identityservice.service.security;

import lombok.RequiredArgsConstructor;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;

import me.sarahlacerda.gua.identityservice.domain.IdentityUser;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;

/**
 * Creating a factor from inside a login, where the session may not have authenticated with one.
 *
 * <p>
 * A sign-in that has only proved the phone number may finish by creating the account's first
 * factor, and by nothing else. So the question "did this account already hold a factor" has to
 * be answered at the moment the new one is written, under the account's row lock, and not
 * earlier when the session was routed: two sessions for the same factorless account can both be
 * routed to setup, and the second one to finish would otherwise add its own PIN or passkey to an
 * account that the first one had just secured. Under the lock, the second session finds a factor
 * it did not authenticate with and is refused before anything is stored.
 *
 * <p>
 * A session that did authenticate with a factor (a PIN sign-in offered a passkey afterwards) may
 * add one freely; that is ordinary enrollment.
 */
@Service
@RequiredArgsConstructor
public class LoginFactorEnrollmentService {

    private final UserSecurityService userSecurityService;
    private final PasskeyService passkeyService;

    /**
     * Sets the first PIN of an account that holds no factor. Always the account's first factor
     * when it returns.
     *
     * @throws LoginFlowException {@code 409 factor_required} when the account already holds a PIN
     *                            or a passkey
     */
    @Transactional
    public void setUpFirstPin(String userId, String pin) {
        IdentityUser user = lockForEnrollment(userId);
        if (user.hasPin() || passkeyService.hasPasskey(userId)) {
            throw factorRequired();
        }
        userSecurityService.setInitialPin(user, pin);
    }

    /**
     * Stores the passkey from a registration ceremony run in a login session.
     *
     * @return whether it is the account's first factor, which is what lets a session that has not
     *         authenticated with a factor complete its sign-in
     * @throws LoginFlowException {@code 409 factor_required} when the session has not authenticated
     *                            with a factor and the account already holds one
     */
    @Transactional
    public boolean registerPasskey(String sessionId, LoginSession session, JsonNode credential) {
        if (!StringUtils.hasText(session.getUserId())) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "passkey_user_unknown",
                    "Passkey setup requires a verified account");
        }
        IdentityUser user = lockForEnrollment(session.getUserId());
        boolean heldAFactor = user.hasPin() || passkeyService.hasPasskey(session.getUserId());
        if (heldAFactor && session.getAuthenticatedFactor() == null) {
            throw factorRequired();
        }
        passkeyService.finishRegistration(sessionId, session, credential);
        return !heldAFactor;
    }

    /**
     * Locks the account row, creating it when the account has none. Two sessions for an account
     * without a row both find nothing to lock; the second to create it fails on the unique
     * {@code user_id} once the first commits. That session lost the race to an account that is
     * now being written, so it gets the same answer as one that found a factor under the lock,
     * and its transaction, including anything it would have stored, rolls back.
     */
    private IdentityUser lockForEnrollment(String userId) {
        try {
            return userSecurityService.lockOrCreateUser(userId);
        } catch (DataIntegrityViolationException ex) {
            throw factorRequired();
        }
    }

    private static LoginFlowException factorRequired() {
        return new LoginFlowException(HttpStatus.CONFLICT, "factor_required",
                "This account is already protected. Sign in with your PIN or passkey.");
    }
}
