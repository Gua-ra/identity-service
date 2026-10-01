// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class AuthorityAfterCommitTest {

    @AfterEach
    void clear() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    @Test
    void workWaitsForTheCommitAndThenRunsOffTheCallingThread() throws Exception {
        AuthorityAfterCommit afterCommit = new AuthorityAfterCommit();
        CompletableFuture<Thread> ranOn = new CompletableFuture<>();
        TransactionSynchronizationManager.initSynchronization();

        afterCommit.run(() -> ranOn.complete(Thread.currentThread()));
        assertThat(ranOn).isNotDone();

        complete(TransactionSynchronization.STATUS_COMMITTED);

        assertThat(ranOn.get(5, TimeUnit.SECONDS)).isNotSameAs(Thread.currentThread());
        afterCommit.shutDown();
    }

    @Test
    void aRolledBackTransactionRunsNothing() {
        List<Runnable> submitted = new ArrayList<>();
        AuthorityAfterCommit afterCommit = new AuthorityAfterCommit(submitted::add);
        TransactionSynchronizationManager.initSynchronization();

        afterCommit.run(() -> { });
        complete(TransactionSynchronization.STATUS_ROLLED_BACK);

        assertThat(submitted).isEmpty();
    }

    @Test
    void workThatThrowsDoesNotThrowIntoTheThreadThatRunsIt() {
        AuthorityAfterCommit afterCommit = new AuthorityAfterCommit(Runnable::run);

        assertThatCode(() -> afterCommit.run(() -> {
            throw new IllegalStateException("the provider is down");
        })).doesNotThrowAnyException();
    }

    private static void complete(int status) {
        for (TransactionSynchronization synchronization : TransactionSynchronizationManager.getSynchronizations()) {
            synchronization.afterCompletion(status);
        }
    }
}
