package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Duration;

import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;

/**
 * The "sign out every other session" a completed account recovery still owes the account.
 *
 * <p>
 * A recovery commits the new PIN, ends its episode and removes the passkeys before the login that
 * carries {@code gua_end_other_sessions} has been issued, let alone handed to the authentication
 * service. Anything that fails in between (a Redis error issuing the code, a browser that never
 * follows the redirect) would otherwise lose the sign-out for good: the episode is over, so a retry
 * is refused, and the next sign-in is an ordinary one with the new PIN. So the mark has three states:
 * <ul>
 * <li><b>owed</b>: written by the recovery transaction just before it commits, and kept for the
 * recovery wait;</li>
 * <li><b>re-issued</b>: while it is owed, every completed sign-in of the account carries the claim,
 * whatever factor it used, not only the recovery's own;</li>
 * <li><b>settled</b>: deleted when the token endpoint issues an ID token carrying the claim. Sign-ins
 * after that are ordinary again.</li>
 * </ul>
 *
 * <p>
 * Known limit: settling records the hand-over, not the sign-out. MAS exchanges the code for the ID
 * token first and acts on the claim only when it finishes the upstream link page for that login.
 * If it never finishes that page (the browser does not follow the redirect to it, or the page
 * fails), the claim is spent without signing anything out, and no later sign-in re-issues it
 * because the mark is already settled. Closing this would need MAS to confirm the sign-out back.
 *
 * <p>
 * Only a completed recovery ever marks an account. The mark lives for the recovery wait. Carrying
 * the claim on a later sign-in can only sign out sessions once more, never let anyone in, and after
 * a recovery the only person who can complete a sign-in is whoever set the new PIN.
 */
@Service
@RequiredArgsConstructor
public class EndOtherSessionsService {

    private static final Logger log = LoggerFactory.getLogger(EndOtherSessionsService.class);

    private static final String KEY_PREFIX = "recovery:end-other-sessions:";

    private final StringRedisTemplate redisTemplate;
    private final IdentityServiceProperties properties;

    /**
     * Records that the account is owed the sign-out. Inside a transaction the write happens just
     * before commit, so a Redis failure rolls the recovery back instead of committing one that
     * owes nothing, and a commit that fails afterwards takes the mark back out.
     */
    public void markOwed(String userId) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            write(userId);
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            private boolean written;

            @Override
            public void beforeCommit(boolean readOnly) {
                write(userId);
                written = true;
            }

            @Override
            public void afterCompletion(int status) {
                if (written && status != STATUS_COMMITTED) {
                    try {
                        redisTemplate.delete(key(userId));
                    } catch (RuntimeException ex) {
                        log.warn("Could not remove the end-other-sessions mark for user {} after its recovery "
                                + "did not commit", userId, ex);
                    }
                }
            }
        });
    }

    /** Whether a completed sign-in of this account must still carry the sign-out. */
    public boolean isOwed(String userId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(key(userId)));
    }

    /** The sign-out has been handed over in an issued ID token. */
    public void settle(String userId) {
        redisTemplate.delete(key(userId));
    }

    private void write(String userId) {
        Duration ttl = properties.getSecurity().getAccountRecoveryWait();
        redisTemplate.opsForValue().set(key(userId), "1", ttl);
    }

    private static String key(String userId) {
        return KEY_PREFIX + userId;
    }
}
