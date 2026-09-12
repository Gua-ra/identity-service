// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.Map;

import org.junit.jupiter.api.Test;

import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The names a scrape really exposes. The Phase 4 exit criteria are quoted in these names, so a panel or
 * an alert built on a name that does not exist would read as "no data" rather than as an error.
 */
class PlacementShadowMetricsTest {

    private IdentityServiceProperties enabled() {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getPlacement().getShadow().setEnabled(true);
        return properties;
    }

    @Test
    void theScrapeExposesExactlyTheDocumentedNames() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        PlacementShadowMetrics metrics = new PlacementShadowMetrics(registry, enabled());

        metrics.classified(PlacementShadowResult.AGREE);
        metrics.classified(PlacementShadowResult.MAS_USERNAME_MISMATCH);
        metrics.published("published");
        metrics.runCompleted(42, 1_757_000_000L);
        metrics.localpartOnConflict(Map.of("fed-primary", "add"));

        String scrape = registry.scrape();
        assertThat(scrape).contains("gua_identity_placement_shadow_total{");
        assertThat(scrape).contains("result=\"agree\"");
        assertThat(scrape).contains("result=\"mas_username_mismatch\"");
        assertThat(scrape).contains("gua_identity_placement_shadow_accounts_scanned");
        assertThat(scrape).contains("gua_identity_placement_shadow_last_success_timestamp");
        assertThat(scrape).contains("gua_identity_placement_publish_total{");
        assertThat(scrape).contains("gua_identity_mas_localpart_on_conflict{");
        assertThat(scrape).contains("homeserver=\"fed-primary\"");
        assertThat(scrape).contains("value=\"add\"");

        // _total is appended to counters and never to gauges; the other spelling would match nothing.
        assertThat(scrape).doesNotContain("gua_identity_placement_shadow_accounts_scanned_total");
        assertThat(scrape).doesNotContain("gua_identity_placement_shadow_last_success_timestamp_total");
    }

    @Test
    void everyResultInTheClosedVocabularyIsRegisteredBeforeItHappens() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);

        new PlacementShadowMetrics(registry, enabled());

        // A fresh pod serves zeros from its first scrape rather than nothing at all.
        String scrape = registry.scrape();
        for (PlacementShadowResult result : PlacementShadowResult.values()) {
            assertThat(scrape).contains("result=\"" + result.tag() + "\"");
        }
    }

    @Test
    void theRunGaugesCarryWhatTheLastRunSaw() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        PlacementShadowMetrics metrics = new PlacementShadowMetrics(registry, enabled());

        metrics.runCompleted(1234, 1_757_000_000L);

        assertThat(registry.get("gua.identity.placement.shadow.accounts.scanned").gauge().value())
                .isEqualTo(1234d);
        assertThat(registry.get("gua.identity.placement.shadow.last.success.timestamp").gauge().value())
                .isEqualTo(1_757_000_000d);
    }

    @Test
    void aDeploymentWithTheFeatureOffRegistersNothingAndPaysNothing() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        PlacementShadowMetrics metrics = new PlacementShadowMetrics(registry, new IdentityServiceProperties());

        metrics.classified(PlacementShadowResult.AGREE);
        metrics.published("published");
        metrics.localpartOnConflict(Map.of("fed-primary", "fail"));

        assertThat(registry.scrape()).doesNotContain("gua_identity_placement");
        assertThat(registry.scrape()).doesNotContain("gua_identity_mas_localpart_on_conflict");
        assertThat(registry.getMeters()).isEmpty();
    }
}
