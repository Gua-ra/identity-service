// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;

/**
 * The series the Phase 4 shadow window is judged by. These are the exact names a scrape exposes:
 *
 * <ul>
 *   <li>{@code gua_identity_placement_shadow_total{result}}, one counter per classification;</li>
 *   <li>{@code gua_identity_placement_shadow_accounts_scanned}, the size of the last run;</li>
 *   <li>{@code gua_identity_placement_shadow_last_success_timestamp}, which is how an alert notices the
 *       job stopped running rather than started disagreeing;</li>
 *   <li>{@code gua_identity_mas_localpart_on_conflict{homeserver,value}}, so {@code add} coming back
 *       after it was set to {@code fail} is visible;</li>
 *   <li>{@code gua_identity_placement_publish_total{result}}, including the conflict a record naming
 *       another homeserver produces.</li>
 * </ul>
 *
 * <p>Prometheus appends {@code _total} to counters and never to gauges, so the two scanned/timestamp
 * gauges carry no such suffix and the two counters do. {@code PlacementShadowMetricsTest} pins every
 * name against a real scrape, because a panel or an alert built on a name that does not exist reads as
 * "no data" rather than as an error.
 *
 * <p>Every counter for the closed result vocabulary is registered eagerly, so a fresh pod serves zeros
 * from its first scrape instead of nothing. Nothing is registered at all while the feature is off: a
 * deployment that has not turned this on pays for none of it.
 */
@Component
public class PlacementShadowMetrics {

    private final MeterRegistry registry;
    private final boolean enabled;

    private final AtomicLong accountsScanned = new AtomicLong();
    private final AtomicLong lastSuccessEpochSeconds = new AtomicLong();
    private final AtomicReference<Map<String, String>> onConflict = new AtomicReference<>(Map.of());

    public PlacementShadowMetrics(MeterRegistry registry, IdentityServiceProperties properties) {
        this.registry = registry;
        this.enabled = properties.getPlacement().getShadow().isEnabled();
        if (!enabled) {
            return;
        }
        for (PlacementShadowResult result : PlacementShadowResult.values()) {
            Counter.builder("gua.identity.placement.shadow")
                    .tag("result", result.tag())
                    .description("Accounts by shadow comparison result")
                    .register(registry);
        }
        Gauge.builder("gua.identity.placement.shadow.accounts.scanned", accountsScanned, AtomicLong::get)
                .description("Accounts the last shadow comparison walked")
                .register(registry);
        Gauge.builder("gua.identity.placement.shadow.last.success.timestamp", lastSuccessEpochSeconds,
                        AtomicLong::get)
                .description("Unix time of the last shadow comparison that completed")
                .register(registry);
    }

    /** Counts one account's classification. */
    public void classified(PlacementShadowResult result) {
        if (enabled) {
            registry.counter("gua.identity.placement.shadow", "result", result.tag()).increment();
        }
    }

    /** Counts one publish attempt, the conflict outcome included. */
    public void published(String result) {
        if (enabled) {
            registry.counter("gua.identity.placement.publish", "result", result).increment();
        }
    }

    /** Records a completed run. */
    public void runCompleted(long scanned, long epochSeconds) {
        accountsScanned.set(scanned);
        lastSuccessEpochSeconds.set(epochSeconds);
    }

    /**
     * Publishes each MAS's effective localpart import policy as a gauge that reads 1 for the value in
     * force. A gauge per observed value, rather than a string, is the only shape Prometheus can alert on.
     */
    public void localpartOnConflict(Map<String, String> byHomeserver) {
        if (!enabled || byHomeserver.isEmpty()) {
            return;
        }
        onConflict.set(Map.copyOf(byHomeserver));
        for (Map.Entry<String, String> entry : byHomeserver.entrySet()) {
            Tags tags = Tags.of("homeserver", entry.getKey(), "value", entry.getValue());
            if (registry.find("gua.identity.mas.localpart.on.conflict").tags(tags).gauge() == null) {
                Gauge.builder("gua.identity.mas.localpart.on.conflict", this,
                                self -> entry.getValue().equals(self.onConflict.get().get(entry.getKey())) ? 1d : 0d)
                        .tags(tags)
                        .description("Effective MAS localpart claims-import on_conflict policy")
                        .register(registry);
            }
        }
    }
}
