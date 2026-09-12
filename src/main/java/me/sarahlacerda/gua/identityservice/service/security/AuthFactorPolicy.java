package me.sarahlacerda.gua.identityservice.service.security;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

/**
 * The one place that answers which authentication factor applies to what.
 *
 * <p>
 * Four questions, and every caller that used to answer one of them locally now asks here
 * instead:
 * <ol>
 * <li>{@link #preferredFactor(String)}: the strongest factor the account actually holds.</li>
 * <li>{@link #loginPolicy(String)}: what signing in may fall back to.</li>
 * <li>{@link #stepUpFor(ReauthOperation)}: what a privileged operation demands.</li>
 * <li>{@link #recoveryFor(String)}: how a lost PIN is recovered.</li>
 * </ol>
 *
 * <p>
 * It exists because those answers had drifted apart. "Does this account need a PIN step"
 * was decided in three services, "does this account already have a passkey" in two
 * controllers, and the service that owns PIN change and recovery could not see passkeys at
 * all, so the recovery side of the product could not even state what it was recovering
 * past. Any one of those sites could be edited into disagreeing with the others without a
 * single test noticing.
 *
 * <h2>Registered is server truth, usable is client truth</h2>
 *
 * <p>
 * Everything this component reports is <b>registered</b>: rows this service can look up.
 * It never reports, accepts or infers <b>usable on this device</b>, which only the client
 * knows and which anyone holding a session can claim. The two must not be confused in
 * either direction:
 * <ul>
 * <li>A client may not say "my passkey is unavailable" and be given a weaker path. That
 * claim costs an attacker nothing, so honouring it would turn the strongest factor into an
 * optional one. There is no such downgrade anywhere in this service and none may be
 * added.</li>
 * <li>Equally, a registered passkey may not be turned into a requirement with no fallback,
 * and may not be used to skip a step-up. Registration says a credential exists, not that
 * this person can use it today. A credential can be left behind on a lost phone or dropped
 * by a credential manager, and the account holds no way to remove or replace one, so
 * requiring it would be permanent lockout: no login, and no recovery either.</li>
 * </ul>
 *
 * <p>
 * The net effect is that a passkey can <em>satisfy</em> a requirement here and can
 * <em>outrank</em> another factor, but it can never <em>remove</em> the fallback underneath
 * it.
 *
 * <h2>What this component deliberately does not decide</h2>
 *
 * <p>
 * It does not gate PIN recovery on a registered passkey. That gate is the missing half of
 * the product rule ("recovery must not let an attacker bypass a registered stronger
 * factor"), and it cannot be closed by refusing recovery: an account whose passkey broke
 * would then have no login and no recovery. Closing it needs a recovery protocol that
 * proves the stronger factor is genuinely gone, which does not exist yet. Until it does,
 * {@link #recoveryFor(String)} reports the stronger factor rather than acting on it, and
 * {@link #recordRecoveryRequest(String)} makes the event visible to whoever is watching
 * the logs. Visible is not the same as prevented, and this comment is not a claim that it
 * is.
 */
@Service
@RequiredArgsConstructor
public class AuthFactorPolicy {

    private static final Logger log = LoggerFactory.getLogger(AuthFactorPolicy.class);

    private final UserSecurityService userSecurityService;
    private final PasskeyService passkeyService;

    /**
     * Whether the account holds a registered passkey AND this deployment has passkeys
     * switched on. Both halves matter: with passkeys disabled a stored credential cannot be
     * asserted, so treating the account as holding one would offer a factor that cannot be
     * used.
     *
     * <p>
     * Server truth about registration only. It says nothing about whether the caller's
     * device can use that credential right now, and no caller may read it as "so demand a
     * passkey" or as "so skip the step-up".
     */
    public boolean passkeyRegistered(String userId) {
        return passkeyService.isEnabled() && passkeyService.hasPasskey(userId);
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
     * What signing in may use for this account.
     *
     * <p>
     * Login is the permissive side by design and stays that way: a PIN step is required
     * exactly when the account has a PIN, and a registered passkey neither adds a step nor
     * removes one. In particular a registered passkey must not cause the PIN step to be
     * skipped, which would let possession of a device stand in for knowledge, nor to be
     * demanded, which would strand a user whose credential broke.
     */
    public LoginPolicy loginPolicy(String userId) {
        boolean passkey = passkeyRegistered(userId);
        boolean pin = pinRegistered(userId);
        List<AuthFactor> fallbacks = pin
                ? List.of(AuthFactor.PIN, AuthFactor.PHONE_OTP)
                : List.of(AuthFactor.PHONE_OTP);
        return new LoginPolicy(strongestHeld(passkey, pin), fallbacks);
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
     * How a lost PIN is recovered, and what else the account holds while that happens.
     *
     * <p>
     * The path itself is unchanged and unconditional: a PIN is restored by proving the
     * number on file, under the dormancy and cooldown gates that
     * {@link UserSecurityService} already enforces. {@code accountAlsoHoldsPasskey} is
     * reported, never applied. Applying it would be the lockout described on this class.
     */
    public RecoveryPolicy recoveryFor(String userId) {
        return new RecoveryPolicy(AuthFactor.PIN, AuthFactor.PHONE_OTP, passkeyRegistered(userId));
    }

    /**
     * Records that PIN recovery was requested, noting whether the account also holds a
     * stronger factor.
     *
     * <p>
     * This is the one thing the cross-factor view buys the recovery flow today. Recovering
     * a knowledge factor on an account that also holds a passkey is the shape of a takeover
     * attempt, and until a recovery protocol exists that can tell that apart from an
     * ordinary lost PIN, the honest thing is to leave the path open and make the event
     * legible. Call it only after the request has been accepted, so a refused attempt does
     * not produce a line, and so this never becomes a way to probe which accounts hold
     * passkeys.
     */
    public void recordRecoveryRequest(String userId) {
        if (passkeyRegistered(userId)) {
            log.warn("PIN recovery requested for user {}, which also holds a registered passkey", userId);
            return;
        }
        log.debug("PIN recovery requested for user {}", userId);
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
     *                  statement that any particular device can use it, and never a reason to
     *                  require a passkey or to skip a step-up
     * @param pin       an account PIN is set
     * @param preferred the strongest of the above, falling back to
     *                  {@link AuthFactor#PHONE_OTP}
     */
    public record RegisteredFactors(boolean passkey, boolean pin, AuthFactor preferred) {
    }

    /**
     * What signing in to this account looks like: the factor to offer first, and everything
     * it may fall back to, strongest first.
     */
    public record LoginPolicy(AuthFactor preferred, List<AuthFactor> fallbacks) {

        /** Whether the login flow must interpose the PIN step. */
        public boolean pinStepRequired() {
            return fallbacks.contains(AuthFactor.PIN);
        }

        public boolean allows(AuthFactor factor) {
            return preferred == factor || fallbacks.contains(factor);
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
     * @param restores                the factor recovery gives back
     * @param provenBy                what the user proves to get it back
     * @param accountAlsoHoldsPasskey whether a stronger factor is registered. Reported for
     *                                visibility and for what a client shows. It is not a
     *                                gate and must not be made one without a protocol that
     *                                can prove the stronger factor is really gone.
     */
    public record RecoveryPolicy(AuthFactor restores, AuthFactor provenBy, boolean accountAlsoHoldsPasskey) {
    }
}
