// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;

// The result and reason labels are closed sets that dashboards and alerts match literally.
// Counters are registered eagerly, and nothing is registered while the feature is off.
@Component
public class PlacementShadowMetrics {

    static final List<String> FAILURE_REASONS = List.of("unknown_homeserver", "error");

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
        for (String reason : FAILURE_REASONS) {
            Counter.builder("gua.identity.placement.shadow.failures")
                    .tag("reason", reason)
                    .description("Accounts the shadow comparison could not classify")
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

    public void classified(PlacementShadowResult result) {
        if (enabled) {
            registry.counter("gua.identity.placement.shadow", "result", result.tag()).increment();
        }
    }

    public void published(String result) {
        if (enabled) {
            registry.counter("gua.identity.placement.publish", "result", result).increment();
        }
    }

    public void failed(String reason) {
        if (enabled) {
            registry.counter("gua.identity.placement.shadow.failures", "reason", reason).increment();
        }
    }

    public void runCompleted(long scanned, long epochSeconds) {
        if (!enabled) {
            return;
        }
        accountsScanned.set(scanned);
        lastSuccessEpochSeconds.set(epochSeconds);
    }

    /** One gauge per observed value, reading 1 for the value in force. */
    public void localpartOnConflict(Map<String, String> byHomeserver) {
        if (!enabled || byHomeserver.isEmpty()) {
            return;
        }
        onConflict.set(Map.copyOf(byHomeserver));
        for (Map.Entry<String, String> entry : byHomeserver.entrySet()) {
            // Copy the strings out: capturing the Map.Entry would keep the caller's map alive for the life of
            // the registry.
            String homeserver = entry.getKey();
            String value = entry.getValue();
            Tags tags = Tags.of("homeserver", homeserver, "value", value);
            if (registry.find("gua.identity.mas.localpart.on.conflict").tags(tags).gauge() == null) {
                Gauge.builder("gua.identity.mas.localpart.on.conflict", this,
                                self -> value.equals(self.onConflict.get().get(homeserver)) ? 1d : 0d)
                        .tags(tags)
                        .description("Effective MAS localpart claims-import on_conflict policy")
                        .register(registry);
            }
        }
    }
}
