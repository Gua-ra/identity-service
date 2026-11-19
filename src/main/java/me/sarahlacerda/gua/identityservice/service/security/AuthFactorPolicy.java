package me.sarahlacerda.gua.identityservice.service.security;

import java.util.List;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

/**
 * The one place that answers which authentication factor applies to what:
 * {@link #registeredFactors(String)} (what the account holds), {@link #loginPolicy(String)} (which
 * factor finishes a sign-in after the phone OTP), {@link #stepUpFor(ReauthOperation)} (what a
 * privileged operation accepts) and {@link #recoveryFor(String)} (what recovery restores and removes).
 *
 * <p>{@code stepUpFor} is published, not enforced: {@code GET /security/pin/status} hands the list to
 * clients, while {@code PhoneChangeService.enforceStepUp} carries the same rule in its own branches.
 * Tests hold the two together. {@code recoveryFor} is a statement only; the delayed recovery runs in
 * {@link AccountRecoveryService}.
 *
 * <p>Held, registered and usable are three different things:
 * <ul>
 * <li><b>Held</b>: a credential row exists. Sign-in routing and recovery read this, so switching
 * passkeys off never turns a passkey-only account into one an SMS code can finish.</li>
 * <li><b>Registered</b>: held and this deployment can assert it. The published status fields report
 * this, so a client is never offered a ceremony the server cannot run.</li>
 * <li><b>Usable on this device</b>: only the client knows. It is never reported, accepted or inferred
 * here, and no client claim selects a weaker path.</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
public class AuthFactorPolicy {

    private final UserSecurityService userSecurityService;
    private final PasskeyService passkeyService;

    /**
     * Whether the account holds a passkey this deployment can assert: a stored credential and passkeys
     * switched on. For the published status fields only. Not a routing input: sign-in, the legacy REST
     * checks and recovery read {@link #passkeyHeld(String)}.
     */
    public boolean passkeyRegistered(String userId) {
        return passkeyService.isEnabled() && passkeyHeld(userId);
    }

    /**
     * Whether a passkey credential is stored for the account, whatever this deployment's passkey
     * switch says. It decides that a sign-in must present the passkey, so switching passkeys off never
     * downgrades a passkey-only account. It says nothing about whether the caller's device can produce
     * the credential.
     */
    public boolean passkeyHeld(String userId) {
        return passkeyService.hasPasskey(userId);
    }

    /**
     * Whether this deployment can run a passkey ceremony at all. Deployment capability read from
     * configuration, not account state, so no caller can assert it. Signup uses it to decide whether
     * to offer passkey enrollment before falling back to the PIN step.
     */
    public boolean passkeysSupported() {
        return passkeyService.isEnabled();
    }

    /** Whether the account has configured an account PIN. Server truth. */
    public boolean pinRegistered(String userId) {
        return userSecurityService.hasPin(userId);
    }

    /**
     * The strongest factor the account holds, which is what a client should offer first. Falls back to
     * {@link AuthFactor#PHONE_OTP}, which every account has.
     */
    public AuthFactor preferredFactor(String userId) {
        return registeredFactors(userId).preferred();
    }

    /** Both registration answers and the ranking that follows from them, read once. */
    public RegisteredFactors registeredFactors(String userId) {
        boolean passkey = passkeyRegistered(userId);
        boolean pin = pinRegistered(userId);
        return new RegisteredFactors(passkey, pin, strongestHeld(passkey, pin));
    }

    /**
     * Which factor finishes signing in to this account once the phone OTP has been verified. The phone
     * OTP never completes a sign-in for any account:
     * <ul>
     * <li>a held PIN puts the PIN step in front of completion; a held passkey may be presented there
     * instead;</li>
     * <li>a held passkey with no PIN makes the passkey required;</li>
     * <li>an account holding neither must set one up before the sign-in completes.</li>
     * </ul>
     * Read off {@link #passkeyHeld(String)}, not {@link #passkeyRegistered(String)}.
     */
    public LoginPolicy loginPolicy(String userId) {
        return new LoginPolicy(passkeyHeld(userId), pinRegistered(userId));
    }

    /**
     * What a privileged operation demands, as a function of the operation only. Narrowing the accepted
     * set by what the account holds could lock an account out; which of the factors an account can
     * produce is settled at the call site.
     *
     * <p>{@code DEACTIVATE} and {@code IDENTITY_RESET} are reported as enforced today: the reauth
     * token alone.
     */
    public StepUpPolicy stepUpFor(ReauthOperation operation) {
        return switch (operation) {
            // A code sent to the number cannot authorize changing that number, so the reauth token alone is
            // never enough.
            case PHONE_CHANGE -> new StepUpPolicy(List.of(AuthFactor.PASSKEY, AuthFactor.PIN), true);
            case DEACTIVATE, IDENTITY_RESET -> new StepUpPolicy(List.of(AuthFactor.PHONE_OTP), false);
        };
    }

    /**
     * What recovering an account restores and what it takes away. Recovery is the same path whatever
     * the account holds: completing it sets a new PIN. {@code removesPasskeys} is reported, never
     * branched on: recovery is not refused to an account that holds a stronger factor.
     */
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

    /**
     * What the account has registered on the server, and which of it ranks highest.
     *
     * @param passkey   a WebAuthn credential exists and this deployment can assert it. Not a statement
     *                  that any device can use it, and not what sign-in routing reads (that is
     *                  {@link AuthFactorPolicy#passkeyHeld(String)})
     * @param pin       an account PIN is set
     * @param preferred the strongest of the above, falling back to {@link AuthFactor#PHONE_OTP}
     */
    public record RegisteredFactors(boolean passkey, boolean pin, AuthFactor preferred) {
    }

    /**
     * What finishing a sign-in to this account demands, read from what it holds.
     *
     * @param passkeyHeld a passkey credential is stored, whether or not passkeys are switched on
     * @param pinHeld     an account PIN is set
     */
    public record LoginPolicy(boolean passkeyHeld, boolean pinHeld) {

        /** The login flow must interpose the PIN step; a passkey assertion is accepted there too. */
        public boolean pinStepRequired() {
            return pinHeld;
        }

        /** The passkey is the only factor this account holds, so the sign-in must present it. */
        public boolean passkeyRequired() {
            return passkeyHeld && !pinHeld;
        }

        /** The account holds no factor, so it must set one up before the sign-in completes. */
        public boolean factorSetupRequired() {
            return !passkeyHeld && !pinHeld;
        }

        /** Whether presenting {@code factor} finishes the sign-in. Never true for the phone OTP. */
        public boolean completesWith(AuthFactor factor) {
            return switch (factor) {
                case PASSKEY -> passkeyHeld;
                case PIN -> pinHeld;
                case PHONE_OTP -> false;
            };
        }
    }

    /**
     * What a privileged operation accepts as its step-up.
     *
     * @param accepted                 the factors that satisfy it, strongest first: the first one
     *                                 the caller can produce settles the step-up
     * @param hardBlockWhenUnsatisfied whether producing none of them refuses the operation outright
     *                                 instead of falling through to the reauth token
     */
    public record StepUpPolicy(List<AuthFactor> accepted, boolean hardBlockWhenUnsatisfied) {

        public boolean accepts(AuthFactor factor) {
            return accepted.contains(factor);
        }

        /**
         * Whether {@code candidate} settles the step-up ahead of {@code other}. False unless
         * both are accepted, so this can rank two ways through, never invent one.
         */
        public boolean outranks(AuthFactor candidate, AuthFactor other) {
            int first = accepted.indexOf(candidate);
            int second = accepted.indexOf(other);
            return first >= 0 && second >= 0 && first < second;
        }
    }

    /**
     * The recovery path for an account.
     *
     * @param restores        the factor recovery gives back
     * @param provenBy        what the user proves before recovery can start
     * @param removesPasskeys whether completing it removes stored passkeys. Reported, not a gate
     */
    public record RecoveryPolicy(AuthFactor restores, AuthFactor provenBy, boolean removesPasskeys) {
    }
}
