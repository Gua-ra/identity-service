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

// Delayed recovery for a caller who proved the phone number but holds no usable factor.
// Every write takes the account row lock and re-evaluates under it.
@Service
@RequiredArgsConstructor
public class AccountRecoveryService {

    private final UserSecurityService userSecurityService;
    private final PasskeyService passkeyService;
    private final EndOtherSessionsService endOtherSessionsService;
    private final IdentityServiceProperties properties;
    private final SecurityAuditLogger auditLogger;
    private final Clock clock;

    @Transactional(readOnly = true)
    public AccountRecoveryState stateFor(String userId) {
        return evaluate(userSecurityService.findUser(userId).orElse(null), clock.instant());
    }

    /** A live episode is returned unchanged, so asking again cannot restart the wait. */
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

    // Signing out other sessions is not done here. The transaction records it as owed and the login carries the
    // claim.
    @Transactional
    public int complete(String userId, String newPin) {
        Instant now = clock.instant();
        IdentityUser user = userSecurityService.lockUser(userId).orElse(null);
        AccountRecoveryState state = evaluate(user, now);
        if (state.status() != Status.READY) {
            throw new AccountRecoveryNotReadyException("Account recovery is not ready to complete", state);
        }
        userSecurityService.applyRecoveredPin(user, newPin);
        int removed = passkeyService.removeAllForUser(userId);
        // Stamped here because the sign-in record that follows the commit is not guaranteed to run.
        userSecurityService.recordAccountActivity(user, now);
        endOtherSessionsService.markOwed(userId);
        auditLogger.accountRecoveryCompleted(userId, removed);
        return removed;
    }

    /** Counts as account activity, so the dormancy period starts again. */
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

    @Transactional(readOnly = true)
    public Optional<AccountRecoveryState> pendingFor(String userId) {
        AccountRecoveryState state = stateFor(userId);
        return state.status() == Status.PENDING || state.status() == Status.READY
                ? Optional.of(state)
                : Optional.empty();
    }

    /** Live wins over dormancy. */
    AccountRecoveryState evaluate(IdentityUser user, Instant now) {
        IdentityServiceProperties.SecurityProperties security = properties.getSecurity();
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

    // Rounded up to the next UTC day so it does not reveal the time of the last sign-in.
    // Rounded to the next minute when short durations are allowed for testing.
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
