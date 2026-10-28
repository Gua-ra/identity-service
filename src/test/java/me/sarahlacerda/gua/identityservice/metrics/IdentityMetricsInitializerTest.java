package me.sarahlacerda.gua.identityservice.metrics;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import me.sarahlacerda.gua.identityservice.exception.SmsRefusedException;
import me.sarahlacerda.gua.identityservice.service.SmsSendGuard;
import me.sarahlacerda.gua.identityservice.service.SmsSender;

class IdentityMetricsInitializerTest {

    /** Named (non-anonymous) impl so the derived provider tag is deterministic ("dummy"). */
    static final class DummySmsSender implements SmsSender {
        @Override
        public void send(String e164PhoneNumber, String messageBody) {
        }
    }

    @Test
    void registersEveryIdentityCounterFamilyAtZeroOnFreshRegistry() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        new IdentityMetricsInitializer(registry, new DummySmsSender());

        assertCounterAtZero(registry, "gua.identity.signup", "result", "success", "country", "unknown");
        assertCounterAtZero(registry, "gua.identity.login", "result", "success");
        for (String flow : OtpVerifyFlow.tagValues()) {
            assertCounterAtZero(registry, "gua.identity.otp.verify", "result", "valid", "flow", flow);
            assertCounterAtZero(registry, "gua.identity.otp.verify", "result", "invalid", "flow", flow);
            assertCounterAtZero(registry, "gua.identity.otp.verify", "result", "exhausted", "flow", flow);
        }
        assertCounterAtZero(registry, "gua.identity.sms.send", "provider", "dummy", "result", "sent");
        assertCounterAtZero(registry, "gua.identity.sms.send", "provider", "dummy", "result", "failed");
        for (SmsRefusedException.Reason reason : SmsRefusedException.Reason.values()) {
            assertCounterAtZero(registry, "gua.identity.sms.refused", "reason", reason.tagValue());
        }
        for (SmsSendGuard.Refusal refusal : SmsSendGuard.Refusal.values()) {
            assertCounterAtZero(registry, "gua.identity.sms.refused", "reason", refusal.tagValue());
        }
    }

    @Test
    void aRefusalIncrementLandsOnThePreRegisteredSeries() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        new IdentityMetricsInitializer(registry, new DummySmsSender());

        // Same idiom OtpService and PhoneChangeOtpService use on a refusal.
        registry.counter("gua.identity.sms.refused", "reason", "destination_unavailable").increment();
        registry.counter("gua.identity.sms.send", "provider", "dummy", "result", "failed").increment();

        assertThat(registry.get("gua.identity.sms.refused").tag("reason", "destination_unavailable").counter()
                .count()).isEqualTo(1.0);
        assertThat(registry.get("gua.identity.sms.send").tag("result", "failed").counter().count()).isEqualTo(1.0);
        assertThat(registry.find("gua.identity.sms.refused").counters())
                .hasSize(SmsRefusedException.Reason.values().length + SmsSendGuard.Refusal.values().length);
    }

    @Test
    void everyFlowsVerifyCounterSurvivesOnARegistryThatRefusesAMixedTagSet() {
        // A meter is keyed by name alone: a later registration with a different tag set records nothing.
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        new IdentityMetricsInitializer(registry, new DummySmsSender());

        for (OtpVerifyFlow flow : OtpVerifyFlow.values()) {
            registry.counter("gua.identity.otp.verify", "result", "valid", "flow", flow.tagValue()).increment();
        }

        for (OtpVerifyFlow flow : OtpVerifyFlow.values()) {
            Counter counter = registry.find("gua.identity.otp.verify")
                    .tag("result", "valid")
                    .tag("flow", flow.tagValue())
                    .counter();
            assertThat(counter)
                    .as("verify counter for flow %s", flow.tagValue())
                    .isNotNull();
            assertThat(counter.count())
                    .as("increments recorded for flow %s", flow.tagValue())
                    .isEqualTo(1.0d);
        }
    }

    @Test
    void prometheusScrapeExposesEveryMetricNameBeforeAnyEvent() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);

        new IdentityMetricsInitializer(registry, new DummySmsSender());

        // What a fresh pod serves on /actuator/prometheus before any traffic: every dashboard metric name
        // must already be there.
        assertThat(registry.scrape())
                .contains("gua_identity_signup_total")
                .contains("gua_identity_login_total")
                .contains("gua_identity_otp_verify_total")
                .contains("gua_identity_sms_send_total")
                .contains("gua_identity_sms_refused_total{reason=\"destination_unavailable\"}")
                .contains("gua_identity_sms_refused_total{reason=\"sign_up_daily_ceiling\"}")
                .contains("gua_identity_sms_refused_total{reason=\"account_daily_ceiling\"}");
    }

    @Test
    void incrementCallSitesReuseThePreRegisteredSeries() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        new IdentityMetricsInitializer(registry, new DummySmsSender());

        // Same idiom the services use when an event happens, flow tag included.
        registry.counter("gua.identity.otp.verify", "result", "valid", "flow", OtpVerifyFlow.PHONE.tagValue())
                .increment();

        assertThat(registry.get("gua.identity.otp.verify")
                .tag("result", "valid")
                .tag("flow", OtpVerifyFlow.PHONE.tagValue())
                .counter()
                .count())
                .isEqualTo(1.0);
        // Still exactly the pre-registered series, three results for each flow, no duplicates.
        assertThat(registry.find("gua.identity.otp.verify").counters())
                .hasSize(3 * OtpVerifyFlow.values().length);
    }

    private static void assertCounterAtZero(MeterRegistry registry, String name, String... tags) {
        Counter counter = registry.find(name).tags(tags).counter();
        assertThat(counter)
                .as("counter %s%s should be registered on startup", name, Arrays.toString(tags))
                .isNotNull();
        assertThat(counter.count()).isZero();
    }
}
