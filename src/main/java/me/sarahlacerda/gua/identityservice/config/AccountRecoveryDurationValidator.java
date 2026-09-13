package me.sarahlacerda.gua.identityservice.config;

import java.time.Duration;

import jakarta.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Refuses to start with a delayed account recovery that is too short to protect anyone.
 *
 * <p>
 * The two durations are the whole of what recovery rests on: the dormancy period keeps a
 * recently used account out of reach, and the wait is the window in which the real account
 * holder sees the banner and cancels. A dormancy or a wait of minutes turns recovery into
 * "whoever holds the SIM owns the account by lunchtime". Both are read from the environment,
 * so one mistyped variable would do that silently in production; failing the start makes it
 * loud instead.
 *
 * <p>
 * {@code identity.security.account-recovery-allow-short-for-testing} lifts the floor so a
 * human can walk a recovery through on a dev deployment. Nothing else may set it.
 */
@Component
public class AccountRecoveryDurationValidator {

    private static final Logger log = LoggerFactory.getLogger(AccountRecoveryDurationValidator.class);

    /** The shortest dormancy or wait a deployment may run without the testing switch. */
    static final Duration FLOOR = Duration.ofHours(24);

    private final IdentityServiceProperties properties;

    public AccountRecoveryDurationValidator(IdentityServiceProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void verify() {
        validate(properties.getSecurity());
    }

    static void validate(IdentityServiceProperties.SecurityProperties security) {
        Duration dormancy = security.getAccountRecoveryDormancy();
        Duration wait = security.getAccountRecoveryWait();
        boolean tooShort = dormancy.compareTo(FLOOR) < 0 || wait.compareTo(FLOOR) < 0;
        if (!tooShort) {
            return;
        }
        if (security.isAccountRecoveryAllowShortForTesting()) {
            log.warn("Account recovery runs with shortened durations (dormancy={}, wait={}). "
                    + "identity.security.account-recovery-allow-short-for-testing is on; this must never "
                    + "be set outside a dev deployment.", dormancy, wait);
            return;
        }
        throw new IllegalStateException("Account recovery dormancy (" + dormancy + ") and wait (" + wait
                + ") must each be at least " + FLOOR + ". Refusing to start. Shorter durations are for dev "
                + "only and need identity.security.account-recovery-allow-short-for-testing=true.");
    }
}
