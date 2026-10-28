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
 * <p>A sign-in that has only proved the phone number may finish by creating the account's first
 * factor, and by nothing else. Whether the account already holds a factor is decided under the
 * account's row lock at write time: two sessions for one factorless account can both be routed to
 * setup, and the second to finish is refused before anything is stored.
 *
 * <p>A session that did authenticate with a factor may add one freely.
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
     * Sets the PIN of an account adding one from settings, after the enrollment session proved the
     * account at {@code ENROLL_STEP_UP}. Unlike {@link #setUpFirstPin}, a held passkey does not block
     * this. The row lock stops two enrollment sessions from both writing a PIN.
     *
     * @throws LoginFlowException {@code 409 pin_already_set} when the account gained a PIN in the
     *                            meantime
     */
    @Transactional
    public void setUpEnrolledPin(String userId, String pin) {
        IdentityUser user = lockForEnrollment(userId);
        if (user.hasPin()) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "pin_already_set",
                    "This account already has a PIN. Change it from your security settings.");
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
     * Locks the account row, creating it when the account has none. Of two sessions creating it, the
     * second fails on the unique {@code user_id} once the first commits and its transaction rolls back.
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
