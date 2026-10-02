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

/**
 * Metrics for the placement shadow comparison. These are the exact names a scrape exposes:
 *
 * <ul>
 *   <li>{@code gua_identity_placement_shadow_total{result}}, one counter per classification;</li>
 *   <li>{@code gua_identity_placement_shadow_accounts_scanned}, the size of the last run;</li>
 *   <li>{@code gua_identity_placement_shadow_last_success_timestamp}, so an alert notices the job
 *       stopped running;</li>
 *   <li>{@code gua_identity_mas_localpart_on_conflict{homeserver,value}};</li>
 *   <li>{@code gua_identity_placement_publish_total{result}};</li>
 *   <li>{@code gua_identity_placement_shadow_failures_total{reason}}, the accounts the run could not
 *       classify.</li>
 * </ul>
 *
 * <p>Both counters carry a closed label set, because panels and alerts match the literal values.
 * {@code result} on the publish counter is a {@code PublishOutcome} ({@code published},
 * {@code conflict}, {@code rejected}, {@code unavailable}) or a skip reason ({@code no_signing_key},
 * {@code bad_account_id}, {@code origin_mismatch}). {@code reason} on the failures counter is
 * {@code unknown_homeserver} or {@code error}.
 *
 * <p>Counters are registered eagerly so a fresh pod serves zeros, and nothing is registered while
 * the feature is off. {@code PlacementShadowMetricsTest} pins every name against a real scrape.
 */
@Component
public class PlacementShadowMetrics {

    /** The closed reason vocabulary of {@code gua_identity_placement_shadow_failures_total}. */
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

    /**
     * Counts one account the run could not classify at all.
     *
     * @param reason one of {@link #FAILURE_REASONS}
     */
    public void failed(String reason) {
        if (enabled) {
            registry.counter("gua.identity.placement.shadow.failures", "reason", reason).increment();
        }
    }

    /** Records a completed run. Gated on the feature like every other method here. */
    public void runCompleted(long scanned, long epochSeconds) {
        if (!enabled) {
            return;
        }
        accountsScanned.set(scanned);
        lastSuccessEpochSeconds.set(epochSeconds);
    }

    /**
     * Publishes each MAS's effective localpart import policy as a gauge that reads 1 for the value in
     * force. A gauge per observed value is the shape Prometheus can alert on.
     */
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
