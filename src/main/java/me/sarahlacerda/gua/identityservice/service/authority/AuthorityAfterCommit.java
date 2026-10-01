// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.annotation.PreDestroy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Runs network I/O for a transition only once its transaction has committed, and off the request thread:
 * in afterCompletion that thread still holds the transaction's JDBC connection.
 */
@Component
public class AuthorityAfterCommit {

    private static final Logger log = LoggerFactory.getLogger(AuthorityAfterCommit.class);

    private static final int WORKERS = 2;
    private static final int QUEUED = 256;

    private final Executor executor;

    @Autowired
    public AuthorityAfterCommit() {
        this(workers());
    }

    public AuthorityAfterCommit(Executor executor) {
        this.executor = executor;
    }

    public void run(Runnable work) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            executor.execute(logged(work));
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                if (status == TransactionSynchronization.STATUS_COMMITTED) {
                    executor.execute(logged(work));
                }
            }
        });
    }

    @PreDestroy
    void shutDown() {
        if (executor instanceof ExecutorService service) {
            service.shutdown();
        }
    }

    private static Runnable logged(Runnable work) {
        return () -> {
            try {
                work.run();
            } catch (RuntimeException ex) {
                log.error("Work after an authority transition failed: {}", ex.toString());
            }
        };
    }

    /** With the queue full the caller runs the work itself, so an alert is delayed and never dropped. */
    private static ExecutorService workers() {
        AtomicInteger number = new AtomicInteger();
        ThreadPoolExecutor pool = new ThreadPoolExecutor(WORKERS, WORKERS, 30L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(QUEUED),
                work -> new Thread(work, "authority-after-commit-" + number.incrementAndGet()),
                new ThreadPoolExecutor.CallerRunsPolicy());
        pool.allowCoreThreadTimeOut(true);
        return pool;
    }
}
