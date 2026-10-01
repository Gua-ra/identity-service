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

// Marks the sign-out a completed recovery owes; while owed, every completed sign-in carries the claim.
// Known limit: settling records the hand-over, not the sign-out, because MAS does not confirm it back.
@Service
@RequiredArgsConstructor
public class EndOtherSessionsService {

    private static final Logger log = LoggerFactory.getLogger(EndOtherSessionsService.class);

    private static final String KEY_PREFIX = "recovery:end-other-sessions:";

    private final StringRedisTemplate redisTemplate;
    private final IdentityServiceProperties properties;

    /** Written just before commit, so a Redis failure rolls the recovery back. */
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

    public boolean isOwed(String userId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(key(userId)));
    }

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
