// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecord;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecordType;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.AuthorityProperties;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

/**
 * The one place that answers every authority question (ADM-009).
 *
 * <p>Deliberately the same shape as {@code AuthFactorPolicy}: a small set of records, methods that state a
 * rule rather than perform a step, and no caller allowed to re-decide any of it locally. The reason is the
 * same too. These rules are not visible in the behaviour of any single method, each of them is one
 * plausible-looking edit away from either a takeover or a lockout, and three of them were added only after
 * a review found the hole their absence left. Spread over the endpoints they would drift; here they can be
 * read end to end.
 *
 * <p>Unlike {@code AuthFactorPolicy}, every question here is <em>decided</em> and not merely stated. The
 * chain has no second implementation of any of it, and the endpoints call these methods rather than
 * carrying the same branches of their own.
 *
 * <h2>What it owns</h2>
 * <ol>
 * <li>The master switch, and the production-adoption gate.</li>
 * <li>The native-session rule: a session still inside the web view cannot start a transition.</li>
 * <li>The step-up scope and its 15-minute age, which the challenge TTL enforces by construction.</li>
 * <li>The fresh-factor hold on the factor actually presented, and the refusal while the account's last
 * completed account recovery is inside that hold.</li>
 * <li>The position and class rules of decision 3 rule 3.</li>
 * <li>Quarantine, and the refusal that would leave no unquarantined active device.</li>
 * <li>Who may oppose what, including the carve-out that lets a named device object when accepting the
 * revocation would leave the signer as the only active device.</li>
 * <li>The rank table of decision 3, and ADM-002 D2's doubling backoff on a cancelled initiation.</li>
 * </ol>
 *
 * <h2>The phone is not here at all</h2>
 *
 * <p>No accepted set below contains {@link AuthFactor#PHONE_OTP}, at any step, in any combination
 * (ADM-009 decision 9). It is not an oversight to be corrected by a later edit: an SMS code proves
 * possession of a number, which a SIM swap also gives, and identifier possession is not account authority.
 * A guard test fails the build if the value appears in this file.
 */
@Service
public class AuthorityPolicy {

    private final IdentityServiceProperties properties;
    private final UserSecurityService userSecurityService;

    public AuthorityPolicy(IdentityServiceProperties properties, UserSecurityService userSecurityService) {
        this.properties = properties;
        this.userSecurityService = userSecurityService;
    }

    // --- The switch -----------------------------------------------------------

    /** Master switch. While false the whole feature is inert and behaviour is exactly as before it existed. */
    public boolean isEnabled() {
        return authority().isEnabled();
    }

    /** 503 for every authority endpoint while the feature is off. */
    public void requireEnabled() {
        if (!isEnabled()) {
            throw new AuthorityTransitionException(HttpStatus.SERVICE_UNAVAILABLE, "authority_disabled",
                    "The account authority chain is not enabled on this deployment.");
        }
    }

    /**
     * Whether an adoption may run at all (ADM-009 gate 3).
     *
     * <p>Separate from the master switch, so a deployment can serve the read endpoint and the device
     * lifecycle of an already-rooted account while adoption itself stays refused. Production adoption waits
     * on ADM-002 Q6: under framework 0x01 the recovery authority key shares the device store with the key
     * it would veto, so an account rooted today cannot be told it has an independent way back.
     */
    public void requireAdoptionPermitted() {
        if (!authority().isProductionAdoption()) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_adoption_not_permitted",
                    "Adoption is not permitted on this deployment.");
        }
    }

    // --- The native-session rule ---------------------------------------------

    /**
     * Refuses a transition submitted by anything but the native app (ADM-009 decision 4 step 1).
     *
     * <p>The authority key lives in the platform keychain or keystore, and the web profile step runs inside
     * an {@code ASWebAuthenticationSession} or a Chrome Custom Tab with no channel to the native signer.
     * That is ADM-008:143, stated here as a rule rather than discovered again at the endpoint.
     *
     * <p>The client id comes from the verified audience of the access token, never from the forwarded
     * downstream-client marker: that marker is client-asserted, and the beta gate that uses it says so.
     * With {@code identity.authority.native-client-ids} empty every caller is refused, which is the safe
     * direction: a deployment that has not said which client is its app has not earned the right to have
     * one of them root an account.
     */
    public void requireNativeSession(Optional<String> clientId) {
        List<String> native_ = authority().getNativeClientIds();
        if (clientId.isEmpty() || !native_.contains(clientId.get())) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_native_session_required",
                    "This step must be taken in the app.");
        }
    }

    /**
     * The browser holds no authority, ever (ADM-009 decision 6).
     *
     * <p>Stated as its own method so the rule has a name a reader can find. There is no flag that lets a
     * web session sign an authority record, and a web session's only reach into the chain is to create a
     * pending approval an authority device then signs on a screen the page does not control.
     */
    public boolean mayHoldAuthority(Optional<String> clientId) {
        return clientId.filter(authority().getNativeClientIds()::contains).isPresent();
    }

    // --- The step-up ----------------------------------------------------------

    /**
     * What a transition accepts as its step-up, as a function of the purpose and nothing else.
     *
     * <p>Not a function of the account, for the reason {@code AuthFactorPolicy.stepUpFor} gives: narrowing
     * the accepted set by what an account happens to hold is how a check turns into a lockout.
     *
     * <p>Every purpose that grants or moves authority hard-blocks, because the alternative on this chain is
     * not a weaker proof, it is no proof. {@code APPROVE} is the one purpose a browser session starts, and
     * it grants nothing on its own: the approval is signed by a device afterwards, so the step-up there is
     * the device's signature rather than a factor.
     */
    public StepUpPolicy stepUpFor(Purpose purpose) {
        return switch (purpose) {
            // A user-verifying passkey assertion, or the account PIN. Never a code sent to the number:
            // O9 asks for a possession proof of this transition, and a SIM swap hands over the number.
            case ADOPT, GRANT, REVOKE, RECOVER -> new StepUpPolicy(List.of(AuthFactor.PASSKEY, AuthFactor.PIN), true);
            // Starting an approval is not an authority transition. It creates a pending object a device
            // must sign, so no factor stands in for that signature and none is asked for here.
            //
            // Nor is opposing one, nor binding a notification registration: both are authorized by a
            // signature from a key the chain already holds active, and for the opposition a factor
            // requirement would be the fresh-factor hold reaching an owner who is trying to say no.
            case APPROVE, OPPOSE, NOTIFY -> new StepUpPolicy(List.of(), false);
        };
    }

    /**
     * What an opposition accepts, and from which opposition onward (ADM-009 decision 4, bounds).
     *
     * <p>The first opposition is deliberately cheap: at {@code seq = 1} the account holds no authority to
     * weigh, so the honest veto is "someone who can already read this account's notifications says no". A
     * second and later opposition needs a step-up, so a stolen bearer session cannot veto the account out
     * of ever gaining authority while remaining account-equivalent itself.
     *
     * <p>At any age, and that is the whole point of stating it here. The fresh-factor hold gates
     * <em>starting</em> a transition and never <em>opposing</em> one: an owner who has just changed their
     * PIN to lock a thief out must not be the one disarmed by it.
     */
    public StepUpPolicy oppositionStepUp() {
        return new StepUpPolicy(List.of(AuthFactor.PASSKEY, AuthFactor.PIN), true);
    }

    /**
     * What removing another install's security-notification registration accepts (ADM-009 gate 2, tier 2).
     *
     * <p>The same two factors, and the fresh-factor hold applied on top by the caller. That hold is the whole
     * defence here: the attacker's only factor after a completed recovery is the PIN that recovery minted, so
     * a tier that accepted any PIN would hand them the one thing they need, which is a quiet channel.
     */
    public StepUpPolicy notificationRemovalStepUp() {
        return new StepUpPolicy(List.of(AuthFactor.PASSKEY, AuthFactor.PIN), true);
    }

    /** Whether the security-notification channel is switched on. Off by default, so gate 2 still blocks. */
    public boolean notificationsEnabled() {
        return authority().getNotifications().isEnabled();
    }

    /** Refuses a registration or a removal while the channel is off, so no push secret is ever read. */
    public void requireNotificationsEnabled() {
        if (!notificationsEnabled()) {
            throw new AuthorityTransitionException(HttpStatus.SERVICE_UNAVAILABLE,
                    "authority_notifications_disabled",
                    "Security notifications are not switched on for this deployment.");
        }
    }

    /** How long a registration counts as a channel with nothing heard from it. */
    public Duration registrationLife() {
        return authority().getNotifications().getRegistrationLife();
    }

    /** How many consecutive permanent transport failures retire a registration. */
    public int registrationFailureLimit() {
        return authority().getNotifications().getFailureLimit();
    }

    /**
     * Refuses a record that would start a window on an account nobody can be told about (ADM-009 gate 2).
     *
     * <p>Stated on the account and checked at submission, because the startup gate can only answer whether the
     * deployment has a transport. A window is the whole security of the transition, and a window whose holder
     * is never told is a delay rather than a control, so the honest answer for an account with no live
     * registration is to refuse the transition rather than to run the window anyway.
     */
    public void requireReachableOutOfBand(boolean reachable) {
        if (!reachable) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_no_notification_channel",
                    "Turn on security notifications on a device of this account before making this change.");
        }
    }

    /** Whether this opposition, counted from one, has to present a factor. */
    public boolean oppositionNeedsStepUp(int oppositionsAlreadyMade) {
        return oppositionsAlreadyMade >= 1;
    }

    /**
     * How long a minted challenge stays spendable, which is also the maximum age of the step-up that minted
     * it (ADM-009 decision 4 steps 2 and 4).
     *
     * <p>One duration for both, so "a step-up no older than the challenge" holds by construction rather
     * than by a second comparison somebody could forget. Startup refuses a configured value over 15 minutes.
     */
    public Duration challengeTtl() {
        return authority().getChallengeTtl();
    }

    /**
     * Refuses a transition whose step-up factor came into existence inside the fresh-factor hold.
     *
     * <p>The same expiring hold the phone change and the PIN change already apply, on the same window, and
     * reached through the same factor-agnostic entry point. It matters more here than there: account
     * recovery mints a caller-chosen PIN, and without this an attacker who completed a recovery presents
     * that PIN days later as the possession proof for rooting the account.
     */
    public void enforceFreshFactorHold(Instant factorCreatedAt) {
        long remaining = userSecurityService.freshFactorHoldRemaining(factorCreatedAt);
        if (remaining > 0) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_factor_too_fresh",
                    "That way of confirming it is you was set up too recently to authorize this.", remaining);
        }
    }

    /**
     * Refuses a transition while the account's last completed account recovery is inside the hold (ADM-009
     * decision 9 rule 3).
     *
     * <p>This is the rule that carries the weight, and it is stated on the account rather than on the
     * session on purpose. A session's completing factor is server-side login state a bearer-authenticated
     * endpoint cannot observe, and the attack re-logs in normally anyway, so a rule written about the
     * session's factor would be inert.
     *
     * <p>Without it the two clocks run independently and the shipped recovery path launders phone
     * possession into an authority transition: a SIM swap completes a recovery, which deletes every passkey,
     * sets an attacker-chosen PIN and revokes the sessions in one transaction, and the transition then
     * accepts that PIN as proof of possession. With it, the total cost is recovery's own dormancy and wait,
     * then this hold, then a window on a channel the attacker does not hold.
     */
    public void enforceRecoveryOutsideHold(String userId) {
        long remaining = userSecurityService.recoveryCompletionHoldRemaining(userId);
        if (remaining > 0) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_recovery_too_recent",
                    "This account was recovered too recently to authorize this.", remaining);
        }
    }

    // --- Position and class (decision 3 rule 3) ------------------------------

    /**
     * Whether this record type is permitted at this position on this class of account.
     *
     * <p>Four rules, and each one closes a route to seizing an account:
     * <ul>
     * <li>{@code AdoptRoot} only on an empty chain of a class 0x00 account, and never otherwise. A second
     * adoption authorized by login factors alone is precisely the seizure O9 rejected, and an attacker who
     * reaches the login factors of a rooted account must not be handed its authority.</li>
     * <li>{@code AuthorityRecovery} only on an account that already holds a committed authority, which for
     * a class 0x01 account is its genesis key and for a class 0x00 account is a completed adoption. It is
     * never a bootstrap account's first record.</li>
     * <li>{@code AuthorityRecovery} through account recovery is refused outright on a class 0x01 account. A
     * genesis-committed authority is replaced only by the key the genesis committed for that purpose, which
     * is what L13.1 means by a genesis-committed threshold.</li>
     * <li>A grant or a revocation only on an account holding at least one unquarantined active device.</li>
     * </ul>
     */
    public void requirePermittedAt(AuthorityRecordType type, Integer authorization, ChainContext context) {
        boolean permitted = switch (type) {
            case ADOPT_ROOT -> context.chainEmpty() && !context.genesisRooted();
            case AUTHORITY_RECOVERY -> context.holdsCommittedAuthority()
                    && !(context.genesisRooted()
                            && authorization != null
                            && authorization == AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY);
            case DEVICE_GRANT, DEVICE_REVOKE -> context.unquarantinedActiveDevices() >= 1;
        };
        if (!permitted) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_position_refused",
                    "This account cannot take that step.");
        }
    }

    // --- Quarantine and the last device -------------------------------------

    /**
     * When a granted device stops being quarantined (ADM-009 decision 5).
     *
     * <p>A grant takes effect on acceptance, because it only adds; what waits is what the granted device may
     * do. While quarantined it may not sign a grant, a revocation or an approval, and it does not count
     * toward the active device a revocation must leave behind. Without that second half a borrowed unlocked
     * phone grants a device and then self-revokes, which is two records, no delay and nothing to oppose, and
     * the owner's own phone is left with no authority.
     */
    public Instant quarantineUntil(Instant now) {
        return now.plus(authority().getOppositionWindow());
    }

    /** Refuses the quarantined device the things decision 5 forbids it. */
    public void requireNotQuarantined(boolean quarantined) {
        if (quarantined) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_device_quarantined",
                    "This device cannot authorize that yet.");
        }
    }

    /**
     * Refuses a revocation that would leave the account with no unquarantined active device.
     *
     * <p>An account with one device that wants to replace it goes through {@code AuthorityRecovery}, which
     * installs the replacement in the same record, rather than through a revocation that would strand it.
     */
    public void requireLeavesAnActiveDevice(int unquarantinedActiveAfter) {
        if (unquarantinedActiveAfter < 1) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_last_device",
                    "That would leave the account with no device that can authorize anything.");
        }
    }

    // --- Who may oppose what -------------------------------------------------

    /**
     * Whether a device may oppose the pending record (ADM-009 decision 5 and decision 7).
     *
     * <p>Three rules and one carve-out:
     * <ul>
     * <li>Any active device other than the one a grant names may oppose that grant, and opposing it revokes
     * the granted device immediately.</li>
     * <li>Any active device may oppose a revocation, <em>except the device the record names</em>, which may
     * not veto its own removal. Without that exclusion an intruder who reached one grant keeps co-authority
     * indefinitely against an owner who does everything right.</li>
     * <li>An {@code AuthorityRecovery} signed by the committed recovery authority key cannot be cancelled by
     * an active device at all, because L13.3 forbids making the possibly stolen active key the veto. An
     * active device's opposition extends the window once and raises the notification, and nothing more. One
     * authorized through account recovery <em>is</em> vetoable immediately, because there a surviving device
     * is the stronger evidence.</li>
     * </ul>
     *
     * <p>The carve-out: on an account with two active devices, where accepting the revocation would leave
     * the <em>signer</em> as the only active device, the named device may oppose. Revision 2's unconditional
     * exclusion handed the mirror-image power to the intruder. A standoff between two devices is a worse
     * outcome for nobody; an eviction the owner is forbidden to object to is a takeover. The standoff is
     * broken by the rank-2 record, which no pending revocation can block and no device can cast.
     */
    public Opposition opposition(AuthorityRecordType pendingType, Integer pendingAuthorization,
            boolean opposerIsNamedDevice, boolean acceptingWouldLeaveSignerAlone) {
        return switch (pendingType) {
            case DEVICE_GRANT -> opposerIsNamedDevice ? Opposition.REFUSED : Opposition.CANCELS;
            case DEVICE_REVOKE -> !opposerIsNamedDevice || acceptingWouldLeaveSignerAlone
                    ? Opposition.CANCELS
                    : Opposition.REFUSED;
            case ADOPT_ROOT -> Opposition.CANCELS;
            case AUTHORITY_RECOVERY -> pendingAuthorization != null
                    && pendingAuthorization == AuthorityRecord.AUTHORIZATION_RECOVERY_KEY
                            ? Opposition.EXTENDS_ONCE
                            : Opposition.CANCELS;
        };
    }

    /**
     * Whether a signed-in session alone may object to this record, without showing that it is an active
     * device.
     *
     * <p>Decision 4 says yes for an adoption: at {@code seq = 1} the account holds no authority to weigh, so
     * the honest veto is "someone who can already read this account's notifications says no". Decision 5 and
     * decision 7's weaker path both say "an active device", which is a stronger claim than a bearer session
     * can make, and an object a device signs to object with is not part of the shipped wire contract. Those
     * are therefore refused here rather than accepted on the session, because accepting them would let a
     * stolen bearer session veto the owner's own revocation of the thief's device, which is the exact
     * inversion decision 5's exclusion exists to prevent.
     */
    public void requireSessionMayOppose(AuthorityRecordType pendingType, Integer pendingAuthorization) {
        boolean sessionIsEnough = pendingType == AuthorityRecordType.ADOPT_ROOT
                || (pendingType == AuthorityRecordType.AUTHORITY_RECOVERY && pendingAuthorization != null
                        && pendingAuthorization == AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY);
        if (!sessionIsEnough) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_opposition_device_required",
                    "Objecting to that step has to come from a device that holds this account's authority.");
        }
    }

    /** What an opposition does to the pending record. */
    public enum Opposition {
        /** The pending record is cancelled and its challenge burned. */
        CANCELS,
        /**
         * The window is extended once and the notification raised, and nothing more. The record still
         * completes: an active key an intruder may hold is not allowed to be the veto (L13.3).
         */
        EXTENDS_ONCE,
        /** This opposer may not object to this record. */
        REFUSED
    }

    // --- Rank, and the backoff on a cancelled initiation ---------------------

    /**
     * The rank of ADM-009 decision 3, which is how competing transitions resolve.
     *
     * <pre>
     * 2  AuthorityRecovery signed by the committed recovery authority key
     * 1  any record signed by an active device key
     * 0  AuthorityRecovery authorized through account recovery
     * </pre>
     *
     * <p>Rank 2 is therefore always reachable, and that is the point: the one record the owner can always
     * land is the one signed by the key they committed for exactly this, and it is not a key an intruder
     * holding devices has.
     *
     * <p>Revision 2 made the pending slot an absolute freeze instead, which was worse than the hole it
     * closed: one intruder device could keep an account frozen forever by cycling a grant and a revocation,
     * and the rule blocked the owner's own escape hatch. This chain adopts ADM-002 D2's existing rank
     * rather than inventing a freeze of its own.
     */
    public short rankOf(AuthorityRecordType type, Integer authorization) {
        if (type != AuthorityRecordType.AUTHORITY_RECOVERY) {
            return 1;
        }
        return authorization != null && authorization == AuthorityRecord.AUTHORIZATION_RECOVERY_KEY
                ? (short) 2
                : (short) 0;
    }

    /**
     * How a submitted record resolves against one already holding a slot.
     *
     * <p>A higher-rank record is accepted while a lower-rank one is pending, and cancels it. An equal-rank
     * record is refused while one is pending. A lower-rank record is refused.
     */
    public SlotOutcome resolveAgainstPending(short submittedRank, short pendingRank) {
        if (submittedRank > pendingRank) {
            return SlotOutcome.CANCELS_PENDING;
        }
        return SlotOutcome.REFUSED;
    }

    /** What happens to a submitted record when another already holds the slot. */
    public enum SlotOutcome {
        /** It outranks the pending record, takes the slot and cancels it. */
        CANCELS_PENDING,
        /** Equal or lower rank: refused, and the caller re-reads with the winner's record in view. */
        REFUSED
    }

    /**
     * The backoff a key set owes after its initiation was cancelled, doubling per cancellation (ADM-002 D2's
     * last sentence).
     *
     * <p>This is what stops the cancel itself becoming the attack. A recovery-key holder who cancels
     * repeatedly pays the doubling on their own next initiation, so the escape hatch stays open once and does
     * not become a way to keep an account permanently unable to transition.
     *
     * <p>Capped at eight windows, because a backoff that grows without bound is a lockout wearing a
     * different name, and the cap is far past the point where a legitimate holder is affected.
     */
    public Duration backoffAfter(int cancellations) {
        if (cancellations <= 0) {
            return Duration.ZERO;
        }
        long multiplier = 1L << Math.min(cancellations - 1, 3);
        return authority().getOppositionWindow().multipliedBy(multiplier);
    }

    /** Refuses an initiation while its key set is inside the doubling backoff. */
    public void requireOutsideBackoff(Instant until, Instant now) {
        if (until != null && now.isBefore(until)) {
            throw new AuthorityTransitionException(HttpStatus.TOO_MANY_REQUESTS, "authority_backoff",
                    "Try that again later.", Math.max(Duration.between(now, until).toSeconds(), 1L));
        }
    }

    /** Refuses a second transition of the same shape inside the cooldown of one window. */
    public void requireOutsideCooldown(Instant cooldownUntil, Instant now) {
        if (cooldownUntil != null && now.isBefore(cooldownUntil)) {
            throw new AuthorityTransitionException(HttpStatus.TOO_MANY_REQUESTS, "authority_cooldown",
                    "Try that again later.", Math.max(Duration.between(now, cooldownUntil).toSeconds(), 1L));
        }
    }

    // --- Windows --------------------------------------------------------------

    /**
     * How long this record waits before it takes effect.
     *
     * <p>A recovery signed by the committed recovery authority key runs ADM-002 D1's delta-r for framework
     * 0x01 rather than the adoption window, which revision 2 had wrong. Everything else runs the opposition
     * window. A grant and a self-revocation take effect at once and never reach this.
     */
    public Duration windowFor(AuthorityRecordType type, Integer authorization) {
        if (type == AuthorityRecordType.AUTHORITY_RECOVERY && authorization != null
                && authorization == AuthorityRecord.AUTHORIZATION_RECOVERY_KEY) {
            return authority().getRecoveryWindow();
        }
        return authority().getOppositionWindow();
    }

    /** One window, which is also the cooldown before another transition of the same shape may open. */
    public Duration oppositionWindow() {
        return authority().getOppositionWindow();
    }

    /** Whether the record takes effect on acceptance rather than after a window. */
    public boolean takesEffectImmediately(AuthorityRecord record) {
        // A grant only adds, and its holder is quarantined; a device removing its own authority reduces
        // what an attacker holding it could do, and delaying that helps nobody.
        return record.type() == AuthorityRecordType.DEVICE_GRANT || record.isSelfRevocation();
    }

    public Duration approvalTtl() {
        return authority().getApprovalTtl();
    }

    public int maxLiveApprovals() {
        return authority().getMaxLiveApprovals();
    }

    private AuthorityProperties authority() {
        return properties.getAuthority();
    }

    /**
     * What the chain says about an account, as the position rules need it.
     *
     * @param chainEmpty                 no record has been accepted
     * @param genesisRooted              the accountId's class byte commits an authority key
     * @param holdsCommittedAuthority    a class 0x01 account's genesis key, or a class 0x00 account's
     *                                   completed adoption
     * @param unquarantinedActiveDevices how many device keys count as this account's authority right now
     */
    public record ChainContext(boolean chainEmpty, boolean genesisRooted, boolean holdsCommittedAuthority,
            int unquarantinedActiveDevices) {
    }

    /**
     * What a transition accepts as its step-up.
     *
     * @param accepted                 the factors that satisfy it, strongest first, and never the phone OTP
     * @param hardBlockWhenUnsatisfied whether producing none of them refuses the operation outright. True
     *                                 for every transition: on this chain the alternative to a proof is not
     *                                 a weaker proof, it is none
     */
    public record StepUpPolicy(List<AuthFactor> accepted, boolean hardBlockWhenUnsatisfied) {

        public boolean accepts(AuthFactor factor) {
            return accepted.contains(factor);
        }

        /** Whether any factor at all settles this purpose. False for the browser-started approval. */
        public boolean required() {
            return !accepted.isEmpty();
        }
    }
}
