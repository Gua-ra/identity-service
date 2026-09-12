package me.sarahlacerda.gua.identityservice.service.account;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord.Origin;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The gauges the Phase 3 rollout is judged by: the names a scrape really exposes, and the promise that a
 * deployment with every flag off pays nothing for a feature it has not turned on.
 */
class AccountGenesisMetricsTest {

    private AccountGenesisRepository repository;
    private AccountScanner scanner;
    private IdentityServiceProperties properties;

    @BeforeEach
    void setUp() {
        repository = mock(AccountGenesisRepository.class);
        scanner = mock(AccountScanner.class);
        properties = new IdentityServiceProperties();
    }

    private void counts(long genesis, long bootstrap, long without) {
        when(repository.countByOrigin(Origin.GENESIS)).thenReturn(genesis);
        when(repository.countByOrigin(Origin.BOOTSTRAP)).thenReturn(bootstrap);
        when(scanner.countAccountsWithoutGenesis()).thenReturn(without);
    }

    @Test
    void theScrapeExposesExactlyTheDocumentedNames() {
        properties.getGenesis().setEnabled(true);
        counts(2, 3, 1);
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);

        new AccountGenesisMetrics(registry, repository, scanner, properties);

        // What a pod actually serves on /actuator/prometheus. These are the names the README, the
        // rollout plan and the ADM-008 exit criteria quote, so a panel built on them must match.
        String scrape = registry.scrape();
        assertThat(scrape).contains("gua_identity_account_genesis{");
        assertThat(scrape).contains("gua_identity_accounts_without_genesis");
        // _total is appended to counters, never to gauges. A dashboard querying the _total spelling
        // would match nothing and read as "no data".
        assertThat(scrape).doesNotContain("gua_identity_account_genesis_total");
        assertThat(scrape).doesNotContain("gua_identity_accounts_without_genesis_total");
    }

    @Test
    void bothOriginsAndTheMissingCountAreReportedFromTheDatabase() {
        properties.getGenesis().setEnabled(true);
        counts(2, 3, 1);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        new AccountGenesisMetrics(registry, repository, scanner, properties);

        assertThat(registry.get("gua.identity.account.genesis").tag("origin", "GENESIS").gauge().value())
                .isEqualTo(2d);
        assertThat(registry.get("gua.identity.account.genesis").tag("origin", "BOOTSTRAP").gauge().value())
                .isEqualTo(3d);
        assertThat(registry.get("gua.identity.accounts.without.genesis").gauge().value()).isEqualTo(1d);
    }

    @Test
    void withEveryFlagOffNothingIsRegisteredAndTheAccountTablesAreNeverScanned() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        new AccountGenesisMetrics(registry, repository, scanner, properties);

        // The scan behind the missing-genesis gauge is a UNION over the account tables with a NOT EXISTS
        // per row, repeated on every scrape. A deployment that never turned the feature on must not pay
        // for it, and must not grow series for a feature that is doing nothing.
        assertThat(registry.getMeters()).isEmpty();
        verifyNoInteractions(scanner);
        verifyNoInteractions(repository);
    }

    @Test
    void theMasterFlagAloneRegistersThem() {
        properties.getGenesis().setEnabled(true);
        counts(0, 0, 0);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        new AccountGenesisMetrics(registry, repository, scanner, properties);

        assertThat(registry.getMeters()).hasSize(3);
    }

    @Test
    void theBackfillFlagAloneRegistersThem() {
        // The backfill can be run before new signups start getting ids, and that is exactly when the
        // missing-genesis count is the number being watched.
        properties.getGenesis().getBootstrapBackfill().setEnabled(true);
        counts(0, 0, 0);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        new AccountGenesisMetrics(registry, repository, scanner, properties);

        assertThat(registry.getMeters()).hasSize(3);
    }

    @Test
    void aValueIsReadFromTheDatabaseAtMostOncePerRefreshInterval() {
        properties.getGenesis().setEnabled(true);
        counts(2, 3, 1);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        new AccountGenesisMetrics(registry, repository, scanner, properties);

        for (int scrape = 0; scrape < 5; scrape++) {
            registry.get("gua.identity.accounts.without.genesis").gauge().value();
        }

        // Cached: a busy scrape interval cannot turn the account scan into a load source.
        org.mockito.Mockito.verify(scanner, org.mockito.Mockito.times(1)).countAccountsWithoutGenesis();
    }
}
