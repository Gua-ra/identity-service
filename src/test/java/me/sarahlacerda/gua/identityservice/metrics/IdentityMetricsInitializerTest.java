package me.sarahlacerda.gua.identityservice.metrics;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import me.sarahlacerda.gua.identityservice.service.SmsSender;

class IdentityMetricsInitializerTest {

    /** Named (non-anonymous) impl so the derived provider tag is deterministic ("dummy"). */
    static final class DummySmsSender implements SmsSender {
        @Override
        public void send(String e164PhoneNumber, String messageBody) {
            // no-op
        }
    }

    @Test
    void registersEveryIdentityCounterFamilyAtZeroOnFreshRegistry() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        new IdentityMetricsInitializer(registry, new DummySmsSender());

        assertCounterAtZero(registry, "gua.identity.signup", "result", "success", "country", "unknown");
        assertCounterAtZero(registry, "gua.identity.login", "result", "success");
        assertCounterAtZero(registry, "gua.identity.otp.verify", "result", "valid");
        assertCounterAtZero(registry, "gua.identity.otp.verify", "result", "invalid");
        assertCounterAtZero(registry, "gua.identity.sms.send", "provider", "dummy", "result", "sent");
        assertCounterAtZero(registry, "gua.identity.sms.send", "provider", "dummy", "result", "failed");
    }

    @Test
    void prometheusScrapeExposesEveryMetricNameBeforeAnyEvent() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);

        new IdentityMetricsInitializer(registry, new DummySmsSender());

        // What a fresh pod serves on /actuator/prometheus before any traffic —
        // every dashboard-referenced metric name must already be there.
        assertThat(registry.scrape())
                .contains("gua_identity_signup_total")
                .contains("gua_identity_login_total")
                .contains("gua_identity_otp_verify_total")
                .contains("gua_identity_sms_send_total");
    }

    @Test
    void incrementCallSitesReuseThePreRegisteredSeries() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        new IdentityMetricsInitializer(registry, new DummySmsSender());

        // Same idiom the services use when an event happens.
        registry.counter("gua.identity.otp.verify", "result", "valid").increment();

        assertThat(registry.get("gua.identity.otp.verify").tag("result", "valid").counter().count())
                .isEqualTo(1.0);
        // Still exactly the two pre-registered series — no duplicates minted.
        assertThat(registry.find("gua.identity.otp.verify").counters()).hasSize(2);
    }

    private static void assertCounterAtZero(MeterRegistry registry, String name, String... tags) {
        Counter counter = registry.find(name).tags(tags).counter();
        assertThat(counter)
                .as("counter %s%s should be registered on startup", name, Arrays.toString(tags))
                .isNotNull();
        assertThat(counter.count()).isZero();
    }
}
