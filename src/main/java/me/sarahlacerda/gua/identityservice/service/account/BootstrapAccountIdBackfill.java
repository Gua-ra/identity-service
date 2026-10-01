package me.sarahlacerda.gua.identityservice.service.account;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;

/** Idempotent and resumable. Each account is minted in its own transaction, so one failure costs one account. */
@Component
@RequiredArgsConstructor
public class BootstrapAccountIdBackfill {

    private static final Logger log = LoggerFactory.getLogger(BootstrapAccountIdBackfill.class);

    private final IdentityServiceProperties properties;
    private final AccountScanner accountScanner;
    private final AccountGenesisRepository repository;
    private final AccountGenesisService accountGenesisService;

    @EventListener(ApplicationReadyEvent.class)
    public void backfillOnStartup() {
        if (!properties.getGenesis().getBootstrapBackfill().isEnabled()) {
            return;
        }
        int minted = run();
        log.info("Bootstrap accountId backfill complete: {} account(s) given an accountId", minted);
    }

    public int run() {
        int batchSize = properties.getGenesis().getBootstrapBackfill().getBatchSize();
        String cursor = "";
        int minted = 0;
        while (true) {
            List<String> batch = accountScanner.nextBatch(cursor, batchSize);
            if (batch.isEmpty()) {
                return minted;
            }
            Set<String> alreadyRooted = new HashSet<>(repository.findExistingUserIds(batch));
            for (String userId : batch) {
                if (!alreadyRooted.contains(userId)) {
                    try {
                        accountGenesisService.bootstrap(userId);
                        minted++;
                    } catch (RuntimeException ex) {
                        log.warn("Could not mint a bootstrap accountId for one account: {}", ex.getMessage());
                    }
                }
            }
            cursor = batch.get(batch.size() - 1);
        }
    }
}
