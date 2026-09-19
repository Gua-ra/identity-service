package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.IdentityUser;
import me.sarahlacerda.gua.identityservice.exception.AccountRecoveryCooldownException;
import me.sarahlacerda.gua.identityservice.exception.AccountRecoveryNotReadyException;
import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryState.Status;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * The delayed account recovery: the way back for someone who proved the phone number but cannot
 * present any factor the account holds.
 *
 * <p>
 * Nothing about it is fast, and that is the protocol. An SMS code proves possession of a number,
 * which a SIM swap also gives. What separates the account holder from whoever holds the SIM is
 * that the holder still has a signed-in device or a factor, so recovery gives them time to use
 * it:
 * <ul>
 * <li>it can only be requested once the account has gone a dormancy period without a completed
 * sign-in;</li>
 * <li>it can only be completed after a waiting period, during which every signed-in app shows a
 * banner with a cancel button, and any sign-in with the PIN or a passkey ends it;</li>
 * <li>completing it sets a new PIN, removes every stored passkey (the premise is that they cannot
 * be used, so a lost device must not sign back in with them) and signs out every other
 * session.</li>
 * </ul>
 *
 * <p>
 * The episode is stamped on {@code identity_users.pin_reset_requested_at} and has exactly one
 * liveness rule, {@code live = stamp != null && now < stamp + life}, used by every status, every
 * writer and the status endpoint the apps poll. A dead stamp is treated as absent, so an episode
 * that was requested and abandoned can never satisfy the wait of the next one.
 *
 * <p>
 * Every write takes the account row lock and re-evaluates under it. Start, complete and cancel
 * race each other and the sign-in writers, and "cancelled and completed" must never both be
 * true.
 *
 * <p>
 * This service sends no SMS. The phone was proved by the OTP step that made recovery available
 * in the first place; a second code would prove nothing new and would be one more message an
 * attacker can trigger.
 */
@Service
@RequiredArgsConstructor
public class AccountRecoveryService {

    private final UserSecurityService userSecurityService;
    private final PasskeyService passkeyService;
    private final EndOtherSessionsService endOtherSessionsService;
    private final IdentityServiceProperties properties;
    private final SecurityAuditLogger auditLogger;
    private final Clock clock;

    /** Where the account stands right now. Reads only. */
    @Transactional(readOnly = true)
    public AccountRecoveryState stateFor(String userId) {
        return evaluate(userSecurityService.findUser(userId).orElse(null), clock.instant());
    }

    /**
     * Opens an episode when recovery is available, and otherwise leaves the account exactly as it
     * was. A live episode is returned unchanged, so asking again can neither restart the wait nor
     * push it out of reach.
     *
     * @throws AccountRecoveryCooldownException when the account completed a sign-in inside the
     *                                          dormancy period
     */
    @Transactional
    public AccountRecoveryState start(String userId, String maskedPhone, String requesterIp) {
        Instant now = clock.instant();
        IdentityUser user = userSecurityService.lockOrCreateUser(userId);
        AccountRecoveryState state = evaluate(user, now);
        switch (state.status()) {
            case PENDING, READY -> {
                return state;
            }
            case TOO_SOON -> throw new AccountRecoveryCooldownException(
                    "Account recovery cannot be started yet",
                    Math.max(state.availableAtEpochSeconds() - now.getEpochSecond(), 1L));
            case AVAILABLE -> {
                userSecurityService.openRecoveryEpisode(user, now);
                auditLogger.accountRecoveryRequested(userId, maskedPhone, requesterIp);
                return evaluate(user, now);
            }
            default -> throw new IllegalStateException("Unhandled recovery status " + state.status());
        }
    }

    /**
     * Completes a ready episode with a new PIN, in one transaction under the row lock: re-check
     * that it is ready, validate the PIN, apply it, end the episode, clear any PIN lock, remove
     * every stored passkey, and count the completion as account activity.
     *
     * <p>
     * Signing out other sessions is not done here. identity-service's own token cutoff does not
     * reach the tokens the apps hold, so the caller finishes the login with a recovery marker the
     * authentication service acts on. The same transaction records that sign-out as owed
     * ({@link EndOtherSessionsService}), so it is not lost when the login cannot be finished.
     *
     * @return how many passkeys were removed
     * @throws AccountRecoveryNotReadyException when the episode is not ready under the lock
     */
    @Transactional
    public int complete(String userId, String newPin) {
        Instant now = clock.instant();
        IdentityUser user = userSecurityService.lockUser(userId).orElse(null);
        AccountRecoveryState state = evaluate(user, now);
        if (state.status() != Status.READY) {
            throw new AccountRecoveryNotReadyException("Account recovery is not ready to complete", state);
        }
        // A malformed or weak PIN is refused here, before anything is written and without counting
        // against the account: it is the new PIN being chosen, not a guess at the old one.
        userSecurityService.applyRecoveredPin(user, newPin);
        int removed = passkeyService.removeAllForUser(userId);
        // Stamped here rather than left to the sign-in record that follows the commit, which is
        // not guaranteed to run: a recovered account must not look dormant enough for another
        // recovery to start straight away.
        userSecurityService.recordAccountActivity(user, now);
        endOtherSessionsService.markOwed(userId);
        auditLogger.accountRecoveryCompleted(userId, removed);
        return removed;
    }

    /**
     * The account holder's cancel from a signed-in app. Ends a live episode and counts as account
     * activity, so the dormancy period starts again and whoever started the recovery cannot simply
     * start another one the next minute.
     *
     * @return whether a live episode was ended. The endpoint answers the same either way
     */
    @Transactional
    public boolean cancel(String userId, String requesterIp) {
        Instant now = clock.instant();
        Optional<IdentityUser> locked = userSecurityService.lockUser(userId);
        if (locked.isEmpty() || !isLive(locked.get(), now)) {
            return false;
        }
        IdentityUser user = locked.get();
        userSecurityService.endRecoveryEpisode(user);
        userSecurityService.recordAccountActivity(user, now);
        auditLogger.accountRecoveryCancelled(userId, requesterIp);
        return true;
    }

    /** The live episode, for the banner the signed-in apps show; empty when none is live. */
    @Transactional(readOnly = true)
    public Optional<AccountRecoveryState> pendingFor(String userId) {
        AccountRecoveryState state = stateFor(userId);
        return state.status() == Status.PENDING || state.status() == Status.READY
                ? Optional.of(state)
                : Optional.empty();
    }

    /**
     * The status rules, in the order they are decided. Live wins over dormancy: an account that
     * is waiting on a recovery reports the recovery, not the sign-in that preceded it.
     */
    AccountRecoveryState evaluate(IdentityUser user, Instant now) {
        IdentityServiceProperties.SecurityProperties security = properties.getSecurity();
        // Published at every status: the screen that explains the two waits has to state the ones
        // this deployment enforces, and the dev target runs them in minutes.
        long dormancy = security.getAccountRecoveryDormancy().toSeconds();
        long wait = security.getAccountRecoveryWait().toSeconds();
        if (user != null && isLive(user, now)) {
            Instant stamp = user.getPinResetRequestedAt();
            Instant completableAt = stamp.plus(security.getAccountRecoveryWait());
            Instant expiresAt = stamp.plus(security.getAccountRecoveryEpisodeLife());
            Status status = now.isBefore(completableAt) ? Status.PENDING : Status.READY;
            return AccountRecoveryState.live(status, ceilSeconds(completableAt), ceilSeconds(expiresAt),
                    dormancy, wait);
        }
        Instant lastLogin = user == null ? null : user.getLastLoginAt();
        if (lastLogin != null) {
            Instant availableAt = lastLogin.plus(security.getAccountRecoveryDormancy());
            if (now.isBefore(availableAt)) {
                return AccountRecoveryState.tooSoon(publishedAvailableAt(availableAt).getEpochSecond(),
                        dormancy, wait);
            }
        }
        return AccountRecoveryState.available(dormancy, wait);
    }

    private boolean isLive(IdentityUser user, Instant now) {
        Instant stamp = user.getPinResetRequestedAt();
        Duration life = properties.getSecurity().getAccountRecoveryEpisodeLife();
        return stamp != null && now.isBefore(stamp.plus(life));
    }

    private static long ceilSeconds(Instant instant) {
        return instant.getNano() == 0 ? instant.getEpochSecond() : instant.getEpochSecond() + 1;
    }

    /**
     * The time a too-soon account is told it can start recovery, rounded up so it does not give
     * away the time of the last sign-in. The start of the next UTC day normally, which is what
     * lets the clients say "try again after Sep 14" and never a time down to the minute; a whole
     * minute when short durations are allowed for testing, where a day would dwarf a dormancy of
     * a few minutes and leave dev QA with nothing to watch. The cooldown's retry-after is derived
     * from this value, so the two always agree.
     *
     * <p>
     * The testing branch buys nothing on the screen itself, and is kept anyway. Every client
     * renders this value as a date with no clock time whichever rounding produced it, so a
     * two-minute wait still reads as a date on a short-duration deployment. What the minute
     * rounding buys is a value that moves at all while QA watches it: rounded to the day, a
     * dormancy of minutes would publish the same instant all day and a run through the flow would
     * look stuck. QA reads the real remaining wait off the refusal's {@code retryAfterSeconds}.
     *
     * <p>
     * Rounding up rather than down, as everywhere else here: the account is never told a moment
     * earlier than the server will agree to.
     */
    private Instant publishedAvailableAt(Instant availableAt) {
        ChronoUnit unit = properties.getSecurity().isAccountRecoveryAllowShortForTesting()
                ? ChronoUnit.MINUTES
                : ChronoUnit.DAYS;
        return ceilTo(availableAt, unit);
    }

    private static Instant ceilTo(Instant instant, ChronoUnit unit) {
        Instant floor = instant.truncatedTo(unit);
        return floor.equals(instant) ? floor : floor.plus(unit.getDuration());
    }
}
