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
 * <p>A recovery commits before the login that carries {@code gua_end_other_sessions} has been
 * issued. Anything that fails in between would otherwise lose the sign-out, so the mark has three
 * states:
 * <ul>
 * <li><b>owed</b>: written by the recovery transaction just before it commits;</li>
 * <li><b>re-issued</b>: while it is owed, every completed sign-in of the account carries the claim,
 * whatever factor it used;</li>
 * <li><b>settled</b>: deleted when the token endpoint issues an ID token carrying the claim.</li>
 * </ul>
 *
 * <p>Known limit: settling records the hand-over, not the sign-out. MAS acts on the claim only when
 * it finishes the upstream link page for that login and does not confirm back, so a claim spent on
 * a login MAS never finishes signs nothing out.
 *
 * <p>Only a completed recovery marks an account. Carrying the claim on a later sign-in can only
 * sign out sessions once more, never let anyone in.
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
     * before commit, so a Redis failure rolls the recovery back, and a commit that fails afterwards
     * takes the mark back out.
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
