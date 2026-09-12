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
 *       another homeserver produces;</li>
 *   <li>{@code gua_identity_placement_shadow_failures_total{reason}}, the accounts the run could not
 *       classify at all.</li>
 * </ul>
 *
 * <p>Both counters carry a <b>closed</b> label set, because a panel or an alert is written against the
 * literal values. {@code result} on the publish counter is one of the four {@code PublishOutcome} values,
 * {@code published}, {@code conflict}, {@code rejected} and {@code unavailable}, or one of the three
 * reasons the reconciler skips an account before ever calling the resolver, {@code no_signing_key},
 * {@code bad_account_id} and {@code origin_mismatch}. {@code reason} on the failures counter is
 * {@code unknown_homeserver} or {@code error}. Adding a value to either is a deliberate edit here.
 *
 * <p>The failures counter exists because the run used to die on the first unreadable account, which
 * stopped {@code last_success_timestamp} advancing and so read as "the job is not running" rather than
 * as "these accounts could not be compared". The run now completes, the timestamp advances, and this is
 * the series an alert watches.
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

    /**
     * Records a completed run. Gated on the feature like every other method here, so a deployment with
     * the comparison off cannot start populating state that the gauges would expose the moment someone
     * registered them unconditionally.
     */
    public void runCompleted(long scanned, long epochSeconds) {
        if (!enabled) {
            return;
        }
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
            // Copied out of the entry deliberately. A lambda capturing the Map.Entry itself would keep a
            // strong reference to the caller's map alive for the life of the registry, once per observed
            // pair, and the gauge only ever needs these two strings.
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
