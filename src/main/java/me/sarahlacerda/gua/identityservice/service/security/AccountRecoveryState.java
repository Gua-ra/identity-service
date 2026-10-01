package me.sarahlacerda.gua.identityservice.service.security;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Instants are whole epoch seconds, rounded up. Fields that do not apply to the status are omitted from the JSON. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AccountRecoveryState(
        Status status,
        Long availableAtEpochSeconds,
        Long completableAtEpochSeconds,
        Long expiresAtEpochSeconds,
        long dormancySeconds,
        long waitSeconds) {

    public enum Status {
        AVAILABLE,
        TOO_SOON,
        PENDING,
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
