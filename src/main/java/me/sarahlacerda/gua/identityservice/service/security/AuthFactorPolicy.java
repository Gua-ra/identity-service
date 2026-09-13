package me.sarahlacerda.gua.identityservice.service.security;

import java.util.List;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

/**
 * The one place that answers which authentication factor applies to what.
 *
 * <p>
 * Four questions. Two of them it decides for every caller that used to decide them
 * locally, and two it states rather than enforces. Which is which is worth knowing before
 * editing any of them, because a reader who takes all four for enforcement will change a
 * declaration and expect the server to follow it:
 * <ol>
 * <li>{@link #registeredFactors(String)}, and {@link #preferredFactor(String)} for one of
 * its halves: what the account holds and which of it ranks highest. Decided here, and read
 * by the status endpoint and by the interactive login state.</li>
 * <li>{@link #loginPolicy(String)}: which factor finishes a sign-in after the phone OTP.
 * Decided here; the interactive login flow and the legacy {@code /otp/verify} path both
 * take their routing from it and keep none of their own.</li>
 * <li>{@link #stepUpFor(ReauthOperation)}: what a privileged operation accepts. Published,
 * not enforced. {@code GET /security/pin/status} hands the list to clients as
 * {@code phoneChangeStepUpFactors}, while {@code PhoneChangeService.enforceStepUp} carries
 * the same rule in its own branches and never asks for it. That is deliberate, and the
 * reason is on {@link #stepUpFor(ReauthOperation)}: a value that could switch the PIN
 * branch or the final refusal off would turn one configuration edit into either a lockout
 * or a bypass. The price is that the two can drift, with nothing but tests holding them
 * together, so editing either one alone makes the server misdescribe what it will
 * take.</li>
 * <li>{@link #recoveryFor(String)}: what recovering an account restores and removes.
 * Written down here, called nowhere. The delayed recovery runs in
 * {@link AccountRecoveryService}; a guard test freezes this method's body as a statement
 * that branches on nothing.</li>
 * </ol>
 *
 * <h2>Held, registered and usable</h2>
 *
 * <p>
 * Three different things, and each question above reads exactly one of them:
 * <ul>
 * <li><b>Held</b>: a credential row exists. {@link #passkeyHeld(String)} and
 * {@link #pinRegistered(String)}. This is what sign-in routing, the legacy REST checks and
 * recovery read, and it ignores whether this deployment currently has passkeys switched on.
 * Switching passkeys off must not turn a passkey-only account into one that an SMS code
 * alone can finish, because that account's next step would be setting a PIN of the SMS
 * holder's choosing.</li>
 * <li><b>Registered</b>: held AND this deployment can assert it.
 * {@link #passkeyRegistered(String)}. This is what the published status fields report, so a
 * client is never offered a ceremony the server cannot run.</li>
 * <li><b>Usable on this device</b>: only the client knows, and anyone holding a session can
 * claim it. It is never reported, accepted or inferred here. There is no field anywhere for a
 * client to say "my passkey is unavailable" and be given a weaker path; that claim costs an
 * attacker nothing.</li>
 * </ul>
 *
 * <h2>Why a held passkey can now be required</h2>
 *
 * <p>
 * An account that holds a passkey and no PIN must present the passkey after the OTP. That
 * used to be refused here as permanent lockout, since a credential left on a lost phone
 * could not be removed or replaced. It is no longer lockout, because the account has a way
 * back that does not need the credential: the delayed recovery in
 * {@link AccountRecoveryService}. Recovery waits out a dormancy period and a waiting period,
 * is cancelled by any sign-in with a factor and by any signed-in app, and on completion sets a
 * new PIN and removes the passkeys it assumed were lost. The wait is what proves the stronger
 * factor is really gone: an account holder who still has it has a week to use it.
 *
 * <p>
 * The PIN stays the fallback underneath a held passkey. An account holding both is asked for
 * the PIN and may present the passkey instead; a held passkey never removes the PIN step's
 * availability, and a PIN never makes the passkey unacceptable.
 */
@Service
@RequiredArgsConstructor
public class AuthFactorPolicy {

    private final UserSecurityService userSecurityService;
    private final PasskeyService passkeyService;

    /**
     * Whether the account holds a passkey this deployment can assert: a stored credential AND
     * passkeys switched on. For the published status fields only, so a client is never
     * offered a ceremony the server cannot run.
     *
     * <p>
     * Not a routing input. Sign-in, the legacy REST checks and recovery read
     * {@link #passkeyHeld(String)}, which does not change meaning when passkeys are switched
     * off.
     */
    public boolean passkeyRegistered(String userId) {
        return passkeyService.isEnabled() && passkeyHeld(userId);
    }

    /**
     * Whether a passkey credential is stored for the account, whatever this deployment's
     * passkey switch says.
     *
     * <p>
     * The stored-credential predicate. It is what decides that a sign-in must present the
     * passkey, so switching passkeys off never downgrades a passkey-only account to one an SMS
     * code alone can finish. Server truth about storage only: it says nothing about whether
     * the caller's device can produce that credential today.
     */
    public boolean passkeyHeld(String userId) {
        return passkeyService.hasPasskey(userId);
    }

    /**
     * Whether this deployment can run a passkey ceremony at all.
     *
     * <p>
     * Deployment capability, not account state. It says nothing about what any account holds,
     * and it is the only sense of "a passkey is unavailable" this service establishes on its
     * own rather than being told: it is read from configuration, so no caller can assert it.
     *
     * <p>
     * Signup asks it to decide whether to offer passkey enrollment before falling back to the
     * PIN step. Offering a ceremony the deployment cannot run would leave a new account looking
     * at a refusal with no second factor set, which is the same lockout shape approached from
     * the other side.
     */
    public boolean passkeysSupported() {
        return passkeyService.isEnabled();
    }

    /** Whether the account has configured an account PIN. Server truth. */
    public boolean pinRegistered(String userId) {
        return userSecurityService.hasPin(userId);
    }

    /**
     * The strongest factor the account actually holds, which is what a client should offer
     * first. Falls back to {@link AuthFactor#PHONE_OTP}, which every account has by
     * construction, since an account is reached through a verified number.
     */
    public AuthFactor preferredFactor(String userId) {
        return registeredFactors(userId).preferred();
    }

    /**
     * Both registration answers and the ranking that follows from them, read once. Callers
     * that need more than one of these, such as the status endpoint a client checks before
     * offering the change-phone flow, should ask for this rather than for each in turn.
     */
    public RegisteredFactors registeredFactors(String userId) {
        boolean passkey = passkeyRegistered(userId);
        boolean pin = pinRegistered(userId);
        return new RegisteredFactors(passkey, pin, strongestHeld(passkey, pin));
    }

    /**
     * Which factor finishes signing in to this account once the phone OTP has been verified.
     *
     * <p>
     * The phone OTP is never enough on its own for an account that holds a factor, and it
     * never counts as the completing factor for any account:
     * <ul>
     * <li>a held PIN puts the PIN step in front of completion; a held passkey may be presented
     * there instead of it;</li>
     * <li>a held passkey with no PIN makes the passkey required;</li>
     * <li>an account holding neither must set one up before the sign-in completes.</li>
     * </ul>
     * Read off {@link #passkeyHeld(String)}, not {@link #passkeyRegistered(String)}, for the
     * reason given there. An account that cannot produce what this demands has the delayed
     * recovery, not a weaker path.
     */
    public LoginPolicy loginPolicy(String userId) {
        return new LoginPolicy(passkeyHeld(userId), pinRegistered(userId));
    }

    /**
     * What a privileged operation demands, as a function of the operation and nothing else.
     *
     * <p>
     * Deliberately not a function of the account. Narrowing the accepted set by what an
     * account happens to hold is how a bare existence check turns into a lockout: an
     * account whose only accepted factor has become unusable would have no way through at
     * all. The accepted set is fixed per operation, and which of those factors a given
     * account can actually produce is settled at the call site, where failing to produce
     * one still leaves the others.
     *
     * <p>
     * {@code DEACTIVATE} and {@code IDENTITY_RESET} are reported as they are enforced
     * today, which is the reauth token alone. That is recorded, not endorsed: it is weaker
     * than the phone change and it is visible here precisely so the gap is in one readable
     * place instead of implied by the absence of code. Raising it is a behaviour change
     * with client work attached and is not part of this one.
     */
    public StepUpPolicy stepUpFor(ReauthOperation operation) {
        return switch (operation) {
            // Re-pointing the number cannot be authorized by a code sent to that same
            // number, so the reauth token is never enough on its own and an account that can
            // produce neither of these is hard-blocked rather than waved through.
            case PHONE_CHANGE -> new StepUpPolicy(List.of(AuthFactor.PASSKEY, AuthFactor.PIN), true);
            case DEACTIVATE, IDENTITY_RESET -> new StepUpPolicy(List.of(AuthFactor.PHONE_OTP), false);
        };
    }

    /**
     * What recovering an account restores, and what it takes away.
     *
     * <p>
     * Recovery is the same path whatever the account holds: after the OTP, a user who cannot
     * present a factor starts a delayed recovery in {@link AccountRecoveryService}, and
     * completing it sets a new PIN. {@code removesPasskeys} is reported, never branched on:
     * recovery is not refused to an account because it holds a stronger factor (that account
     * would then have no way back), and the passkeys are removed on completion because the
     * premise of recovering is that they cannot be used.
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
     * @param passkey   a WebAuthn credential exists and this deployment can assert it. NOT a
     *                  statement that any particular device can use it, never a reason to skip
     *                  a step-up, and not what sign-in routing reads (that is
     *                  {@link AuthFactorPolicy#passkeyHeld(String)})
     * @param pin       an account PIN is set
     * @param preferred the strongest of the above, falling back to
     *                  {@link AuthFactor#PHONE_OTP}
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
     * @param accepted                 the factors that satisfy it, strongest first. The
     *                                 order is the precedence the enforcing call site
     *                                 implements: the first one the caller can produce
     *                                 settles the step-up, and the rest stay available to
     *                                 callers who cannot produce it.
     * @param hardBlockWhenUnsatisfied whether producing none of them refuses the operation
     *                                 outright rather than falling through to the reauth
     *                                 token
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
     * @param provenBy        what the user proves before recovery can start; the waiting period
     *                        is what proves they no longer hold anything stronger
     * @param removesPasskeys whether completing it removes stored passkeys, which it does
     *                        whenever the account holds one. Reported, not a gate: recovery is
     *                        never refused because the account holds a stronger factor
     */
    public record RecoveryPolicy(AuthFactor restores, AuthFactor provenBy, boolean removesPasskeys) {
    }
}
