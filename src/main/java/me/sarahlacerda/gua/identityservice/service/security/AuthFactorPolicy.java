package me.sarahlacerda.gua.identityservice.service.security;

import java.util.List;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

// Held means a credential row exists; registered means held and assertable on this deployment.
// Sign-in routing reads held, so switching passkeys off never downgrades a passkey-only account.
@Service
@RequiredArgsConstructor
public class AuthFactorPolicy {

    private final UserSecurityService userSecurityService;
    private final PasskeyService passkeyService;

    /** For published status fields only. Not a routing input. */
    public boolean passkeyRegistered(String userId) {
        return passkeyService.isEnabled() && passkeyHeld(userId);
    }

    public boolean passkeyHeld(String userId) {
        return passkeyService.hasPasskey(userId);
    }

    /** Deployment capability read from configuration, not account state. */
    public boolean passkeysSupported() {
        return passkeyService.isEnabled();
    }

    public boolean pinRegistered(String userId) {
        return userSecurityService.hasPin(userId);
    }

    /** Falls back to PHONE_OTP, which every account has. */
    public AuthFactor preferredFactor(String userId) {
        return registeredFactors(userId).preferred();
    }

    public RegisteredFactors registeredFactors(String userId) {
        boolean passkey = passkeyRegistered(userId);
        boolean pin = pinRegistered(userId);
        return new RegisteredFactors(passkey, pin, strongestHeld(passkey, pin));
    }

    /** The phone OTP never completes a sign-in for any account. */
    public LoginPolicy loginPolicy(String userId) {
        return new LoginPolicy(passkeyHeld(userId), pinRegistered(userId));
    }

    // Depends on the operation only: narrowing by what the account holds could lock an account out.
    // DEACTIVATE and IDENTITY_RESET require only the reauth token today.
    public StepUpPolicy stepUpFor(ReauthOperation operation) {
        return switch (operation) {
            // A code sent to the number cannot authorize changing that number, so the reauth token alone is
            // never enough.
            case PHONE_CHANGE -> new StepUpPolicy(List.of(AuthFactor.PASSKEY, AuthFactor.PIN), true);
            case DEACTIVATE, IDENTITY_RESET -> new StepUpPolicy(List.of(AuthFactor.PHONE_OTP), false);
        };
    }

    // removesPasskeys is reported, never branched on: recovery is not refused to an account that holds a
    // stronger factor.
    public RecoveryPolicy recoveryFor(String userId) {
        return new RecoveryPolicy(AuthFactor.PIN, AuthFactor.PHONE_OTP, passkeyHeld(userId));
    }

    private static AuthFactor strongestHeld(boolean passkey, boolean pin) {
        if (passkey) {
            return AuthFactor.PASSKEY;
        }
        if (pin) {
            return AuthFactor.PIN;
        }
        return AuthFactor.PHONE_OTP;
    }

    public record RegisteredFactors(boolean passkey, boolean pin, AuthFactor preferred) {
    }

    public record LoginPolicy(boolean passkeyHeld, boolean pinHeld) {

        /** A passkey assertion is accepted at the PIN step too. */
        public boolean pinStepRequired() {
            return pinHeld;
        }

        public boolean passkeyRequired() {
            return passkeyHeld && !pinHeld;
        }

        public boolean factorSetupRequired() {
            return !passkeyHeld && !pinHeld;
        }

        /** Never true for the phone OTP. */
        public boolean completesWith(AuthFactor factor) {
            return switch (factor) {
                case PASSKEY -> passkeyHeld;
                case PIN -> pinHeld;
                case PHONE_OTP -> false;
            };
        }
    }

    // accepted is ordered strongest first. hardBlockWhenUnsatisfied refuses the operation when none can be
    // produced.
    public record StepUpPolicy(List<AuthFactor> accepted, boolean hardBlockWhenUnsatisfied) {

        public boolean accepts(AuthFactor factor) {
            return accepted.contains(factor);
        }

        /** False unless both are accepted. */
        public boolean outranks(AuthFactor candidate, AuthFactor other) {
            int first = accepted.indexOf(candidate);
            int second = accepted.indexOf(other);
            return first >= 0 && second >= 0 && first < second;
        }
    }

    public record RecoveryPolicy(AuthFactor restores, AuthFactor provenBy, boolean removesPasskeys) {
    }
}
