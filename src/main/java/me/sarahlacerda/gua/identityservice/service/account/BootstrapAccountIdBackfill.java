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

/**
 * Gives every account that predates account genesis a bootstrap accountId (ADM-001 L5 path B1).
 *
 * <p>Idempotent and resumable. It walks accounts in user-id order in batches, skips the ones that
 * already hold a genesis row, and mints one for the rest; a second run therefore mints nothing, and a
 * run interrupted halfway continues from where the ordering left off rather than starting over. Each
 * account is minted in its own transaction, so one failure costs one account, not the batch.
 *
 * <p>Gated by {@code identity.genesis.bootstrap-backfill.enabled}, separately from the master switch,
 * so existing accounts can be filled in before or after new signups start getting ids.
 */
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

    /**
     * Runs the backfill to completion.
     *
     * @return how many accounts were given an accountId by this run
     */
    public int run() {
        int batchSize = properties.getGenesis().getBootstrapBackfill().getBatchSize();
        String cursor = "";
        int minted = 0;
        while (true) {
            List<String> batch = accountScanner.nextBatch(cursor, batchSize);
            if (batch.isEmpty()) {
                return minted;
            }
            // One query per batch tells us which of these already have a row, so a rerun over a fully
            // backfilled deployment does no writes at all.
            Set<String> alreadyRooted = new HashSet<>(repository.findExistingUserIds(batch));
            for (String userId : batch) {
                if (!alreadyRooted.contains(userId)) {
                    try {
                        accountGenesisService.bootstrap(userId);
                        minted++;
                    } catch (RuntimeException ex) {
                        // Never let one account stop the sweep; the next run picks it up again.
                        log.warn("Could not mint a bootstrap accountId for one account: {}", ex.getMessage());
                    }
                }
            }
            cursor = batch.get(batch.size() - 1);
        }
    }
}
