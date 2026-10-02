package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;

/**
 * The owed sign-out is written with the recovery or not at all: just before its commit, and taken
 * back out when the commit does not happen.
 */
class EndOtherSessionsServiceTest {

    private static final String USER = "@alice:gua.global";
    private static final String KEY = "recovery:end-other-sessions:" + USER;

    private StringRedisTemplate redisTemplate;
    private ValueOperations<String, String> valueOps;
    private EndOtherSessionsService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        redisTemplate = mock(StringRedisTemplate.class);
        valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getSecurity().setAccountRecoveryWait(Duration.ofDays(7));
        service = new EndOtherSessionsService(redisTemplate, properties);
    }

    @AfterEach
    void tearDown() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    private static List<TransactionSynchronization> inTransaction(Runnable work) {
        TransactionSynchronizationManager.initSynchronization();
        work.run();
        return TransactionSynchronizationManager.getSynchronizations();
    }

    @Test
    void outsideATransactionTheMarkIsWrittenAtOnceForTheRecoveryWait() {
        service.markOwed(USER);

        verify(valueOps).set(KEY, "1", Duration.ofDays(7));
    }

    @Test
    void insideATransactionTheMarkIsWrittenJustBeforeCommitAndKeptWhenItCommits() {
        List<TransactionSynchronization> synchronizations = inTransaction(() -> service.markOwed(USER));

        verifyNoInteractions(valueOps);
        synchronizations.forEach(sync -> sync.beforeCommit(false));
        verify(valueOps).set(KEY, "1", Duration.ofDays(7));

        synchronizations.forEach(sync -> sync.afterCompletion(TransactionSynchronization.STATUS_COMMITTED));
        verify(redisTemplate, never()).delete(anyString());
    }

    @Test
    void aFailedWriteFailsTheCommitSoTheRecoveryRollsBack() {
        doThrow(new IllegalStateException("redis down")).when(valueOps).set(any(), any(), any(Duration.class));
        List<TransactionSynchronization> synchronizations = inTransaction(() -> service.markOwed(USER));

        assertThatThrownBy(() -> synchronizations.forEach(sync -> sync.beforeCommit(false)))
                .isInstanceOf(IllegalStateException.class);
        synchronizations.forEach(sync -> sync.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));

        // Nothing was written, so nothing is taken back out, including a mark an earlier recovery left.
        verify(redisTemplate, never()).delete(anyString());
    }

    @Test
    void aCommitThatFailsAfterTheWriteTakesTheMarkBackOut() {
        List<TransactionSynchronization> synchronizations = inTransaction(() -> service.markOwed(USER));

        synchronizations.forEach(sync -> sync.beforeCommit(false));
        synchronizations.forEach(sync -> sync.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));

        verify(redisTemplate).delete(eq(KEY));
    }

    @Test
    void aRollbackBeforeCommitWritesNothing() {
        List<TransactionSynchronization> synchronizations = inTransaction(() -> service.markOwed(USER));

        synchronizations.forEach(sync -> sync.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));

        verifyNoInteractions(valueOps);
        verify(redisTemplate, never()).delete(anyString());
    }

    @Test
    void owedUntilSettled() {
        when(redisTemplate.hasKey(KEY)).thenReturn(true);
        assertThat(service.isOwed(USER)).isTrue();

        service.settle(USER);
        verify(redisTemplate).delete(KEY);

        when(redisTemplate.hasKey(KEY)).thenReturn(false);
        assertThat(service.isOwed(USER)).isFalse();
        when(redisTemplate.hasKey(KEY)).thenReturn(null);
        assertThat(service.isOwed(USER)).isFalse();
    }
}
