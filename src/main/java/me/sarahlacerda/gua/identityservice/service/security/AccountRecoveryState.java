package me.sarahlacerda.gua.identityservice.service.security;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Where an account stands with the delayed account recovery, as the login flow publishes it.
 *
 * <p>
 * Every instant is whole epoch seconds, rounded up, so a client told "you can finish after X"
 * is never told a moment earlier than the server will agree. Fields that do not apply to the
 * status are null and left out of the JSON.
 *
 * @param status                    see {@link Status}
 * @param availableAtEpochSeconds   {@link Status#TOO_SOON} only: when recovery may be requested.
 *                                  Rounded up to the start of the next UTC day, so it does not
 *                                  reveal the time of the account's last sign-in; rounded up to
 *                                  the next whole minute when
 *                                  {@code account-recovery-allow-short-for-testing} is on, so QA
 *                                  can see the value move. Clients render it as a date either way
 * @param completableAtEpochSeconds {@link Status#PENDING} and {@link Status#READY}: when the wait
 *                                  is over
 * @param expiresAtEpochSeconds     {@link Status#PENDING} and {@link Status#READY}: when the
 *                                  episode stops being live and must be requested again
 * @param dormancySeconds           how long the account must go unused before a recovery may be
 *                                  started, and
 * @param waitSeconds               how long a started recovery waits before it can be finished.
 *                                  Both are configuration, not episode state, so both are present
 *                                  at every status: the screen that explains the two waits must
 *                                  state what this deployment enforces
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AccountRecoveryState(
        Status status,
        Long availableAtEpochSeconds,
        Long completableAtEpochSeconds,
        Long expiresAtEpochSeconds,
        long dormancySeconds,
        long waitSeconds) {

    public enum Status {
        /** No live episode and the account has been dormant long enough: recovery may be started. */
        AVAILABLE,
        /** No live episode, and the account completed a sign-in inside the dormancy period. */
        TOO_SOON,
        /** An episode is live and still waiting. */
        PENDING,
        /** An episode is live and its wait is over: it can be completed with a new PIN. */
        READY
    }

    static AccountRecoveryState available(long dormancySeconds, long waitSeconds) {
        return new AccountRecoveryState(Status.AVAILABLE, null, null, null, dormancySeconds, waitSeconds);
    }

    static AccountRecoveryState tooSoon(long availableAtEpochSeconds, long dormancySeconds, long waitSeconds) {
        return new AccountRecoveryState(Status.TOO_SOON, availableAtEpochSeconds, null, null,
                dormancySeconds, waitSeconds);
    }

    static AccountRecoveryState live(Status status, long completableAtEpochSeconds, long expiresAtEpochSeconds,
            long dormancySeconds, long waitSeconds) {
        return new AccountRecoveryState(status, null, completableAtEpochSeconds, expiresAtEpochSeconds,
                dormancySeconds, waitSeconds);
    }
}
