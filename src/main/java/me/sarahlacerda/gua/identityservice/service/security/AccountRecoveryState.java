package me.sarahlacerda.gua.identityservice.service.security;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Where an account stands with the delayed account recovery, as the login flow publishes it.
 *
 * <p>Every instant is whole epoch seconds, rounded up, so a client is never told a moment earlier
 * than the server will agree to. Fields that do not apply to the status are null and omitted from
 * the JSON.
 *
 * @param status                    see {@link Status}
 * @param availableAtEpochSeconds   {@link Status#TOO_SOON} only: when recovery may be requested,
 *                                  rounded up to the start of the next UTC day (the next minute
 *                                  when short durations are allowed for testing)
 * @param completableAtEpochSeconds {@link Status#PENDING} and {@link Status#READY}: when the wait
 *                                  is over
 * @param expiresAtEpochSeconds     {@link Status#PENDING} and {@link Status#READY}: when the
 *                                  episode stops being live and must be requested again
 * @param dormancySeconds           how long the account must go unused before a recovery may be
 *                                  started
 * @param waitSeconds               how long a started recovery waits before it can be finished.
 *                                  Both are configuration, so both are present at every status
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
