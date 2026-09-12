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

/**
 * The two gauges Phase 3 is watched by:
 *
 * <ul>
 *   <li>{@code gua_identity_account_genesis{origin}}, how many accounts are rooted in a genesis
 *       and how many are bootstrap, which is the audit split ADM-001 L5 asks to be able to see;</li>
 *   <li>{@code gua_identity_accounts_without_genesis}, which must reach zero and stay there before any
 *       later phase may propose reading a placement record for routing.</li>
 * </ul>
 *
 * <p>Those are the exact names a scrape exposes. Both are gauges, and the Prometheus registry appends
 * {@code _total} to counters only, so neither name carries that suffix; {@code AccountGenesisMetricsTest}
 * pins the scraped names so a panel or an alert built on them cannot come back "no data", which is the
 * failure {@code IdentityMetricsInitializer} was written to prevent. Counters are not an option here:
 * both counts fall as the backfill runs, and the second one exists to reach zero.
 *
 * <p>Registered only while the feature is switched on, under either flag. With everything off no new
 * series appear and, more to the point, {@link AccountScanner#countAccountsWithoutGenesis()} never runs:
 * it is a full pass over the account tables, and a feature nobody turned on must cost nothing.
 *
 * <p>Each value is read from the database at most once per {@link #REFRESH} interval and cached in
 * between, so a busy Prometheus scrape cannot turn a gauge into a load source. Registered eagerly at
 * construction, in the pattern {@code IdentityMetricsInitializer} documents, so the series exist on a
 * fresh pod's first scrape instead of appearing as "no data".
 */
@Component
public class AccountGenesisMetrics {

    private static final Logger log = LoggerFactory.getLogger(AccountGenesisMetrics.class);

    private static final Duration REFRESH = Duration.ofSeconds(60);

    private final Cached genesisCount;
    private final Cached bootstrapCount;
    private final Cached withoutGenesisCount;

    public AccountGenesisMetrics(MeterRegistry metrics, AccountGenesisRepository repository,
            AccountScanner accountScanner, IdentityServiceProperties properties) {
        // Wrapping a supplier reads nothing; only a scrape of a registered gauge does.
        this.genesisCount = new Cached(() -> repository.countByOrigin(Origin.GENESIS));
        this.bootstrapCount = new Cached(() -> repository.countByOrigin(Origin.BOOTSTRAP));
        this.withoutGenesisCount = new Cached(accountScanner::countAccountsWithoutGenesis);

        GenesisProperties genesis = properties.getGenesis();
        if (!genesis.isEnabled() && !genesis.getBootstrapBackfill().isEnabled()) {
            // Inert, which is what every flag being off promises: no series, and no scan behind them.
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

    /** A value read at most once per {@link #REFRESH}, which never propagates a database failure. */
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
                // A scrape must never fail because the database is briefly unavailable; serve the last
                // value and try again on the next one.
                log.debug("Could not refresh an account genesis gauge: {}", ex.getMessage());
                return current.value();
            }
        }

        private record Snapshot(Instant takenAt, double value) {
        }
    }
}
