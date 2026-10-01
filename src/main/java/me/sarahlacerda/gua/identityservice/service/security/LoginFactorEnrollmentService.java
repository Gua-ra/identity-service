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

// Whether the account already holds a factor is decided under the row lock at write time,
// so two sessions for one factorless account cannot both add a factor.
@Service
@RequiredArgsConstructor
public class LoginFactorEnrollmentService {

    private final UserSecurityService userSecurityService;
    private final PasskeyService passkeyService;

    @Transactional
    public void setUpFirstPin(String userId, String pin) {
        IdentityUser user = lockForEnrollment(userId);
        if (user.hasPin() || passkeyService.hasPasskey(userId)) {
            throw factorRequired();
        }
        userSecurityService.setInitialPin(user, pin);
    }

    /** Unlike setUpFirstPin, a held passkey does not block this. */
    @Transactional
    public void setUpEnrolledPin(String userId, String pin) {
        IdentityUser user = lockForEnrollment(userId);
        if (user.hasPin()) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "pin_already_set",
                    "This account already has a PIN. Change it from your security settings.");
        }
        userSecurityService.setInitialPin(user, pin);
    }

    /** Returns whether it is the account's first factor. */
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

    /** A session that loses the row-creation race fails on the unique user_id and rolls back. */
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
