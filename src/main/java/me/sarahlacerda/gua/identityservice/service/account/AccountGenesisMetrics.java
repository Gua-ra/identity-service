package me.sarahlacerda.gua.identityservice.service.account;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.GenesisProperties;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord.Origin;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;

/** Registered only while the feature is on. Each value is read from the database at most once per REFRESH. */
@Component
public class AccountGenesisMetrics {

    private static final Logger log = LoggerFactory.getLogger(AccountGenesisMetrics.class);

    private static final Duration REFRESH = Duration.ofSeconds(60);

    private final Cached genesisCount;
    private final Cached bootstrapCount;
    private final Cached withoutGenesisCount;

    public AccountGenesisMetrics(MeterRegistry metrics, AccountGenesisRepository repository,
            AccountScanner accountScanner, IdentityServiceProperties properties) {
        this.genesisCount = new Cached(() -> repository.countByOrigin(Origin.GENESIS));
        this.bootstrapCount = new Cached(() -> repository.countByOrigin(Origin.BOOTSTRAP));
        this.withoutGenesisCount = new Cached(accountScanner::countAccountsWithoutGenesis);

        GenesisProperties genesis = properties.getGenesis();
        if (!genesis.isEnabled() && !genesis.getBootstrapBackfill().isEnabled()) {
            return;
        }

        Gauge.builder("gua.identity.account.genesis", genesisCount::get)
                .tag("origin", Origin.GENESIS.name())
                .description("Accounts whose identity is rooted in a registered AccountGenesis")
                .register(metrics);
        Gauge.builder("gua.identity.account.genesis", bootstrapCount::get)
                .tag("origin", Origin.BOOTSTRAP.name())
                .description("Accounts holding a bootstrap accountId")
                .register(metrics);
        Gauge.builder("gua.identity.accounts.without.genesis", withoutGenesisCount::get)
                .description("Accounts that hold no accountId at all")
                .register(metrics);
    }

    private static final class Cached {

        private final Supplier<Long> source;
        private final AtomicReference<Snapshot> snapshot = new AtomicReference<>(new Snapshot(Instant.EPOCH, 0d));

        private Cached(Supplier<Long> source) {
            this.source = source;
        }

        private double get() {
            Snapshot current = snapshot.get();
            if (Duration.between(current.takenAt(), Instant.now()).compareTo(REFRESH) < 0) {
                return current.value();
            }
            try {
                double value = source.get();
                snapshot.set(new Snapshot(Instant.now(), value));
                return value;
            } catch (RuntimeException ex) {
                // A scrape must never fail because the database is briefly unavailable.
                log.debug("Could not refresh an account genesis gauge: {}", ex.getMessage());
                return current.value();
            }
        }

        private record Snapshot(Instant takenAt, double value) {
        }
    }
}
