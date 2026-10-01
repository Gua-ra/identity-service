package me.sarahlacerda.gua.identityservice.metrics;

import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import me.sarahlacerda.gua.identityservice.service.SmsSender;

/** Registers the counters at startup so they read 0, not "no data", before the first increment. */
@Component
public class IdentityMetricsInitializer {

    public IdentityMetricsInitializer(MeterRegistry metrics, SmsSender smsSender) {
        Counter.builder("gua.identity.signup")
                .tag("result", "success")
                .tag("country", "unknown")
                .register(metrics);

        Counter.builder("gua.identity.login")
                .tag("result", "success")
                .register(metrics);

        // Micrometer keys a meter by name: every registration of a counter must carry the same tag keys.
        for (String flow : OtpVerifyFlow.tagValues()) {
            Counter.builder("gua.identity.otp.verify").tag("result", "valid").tag("flow", flow).register(metrics);
            Counter.builder("gua.identity.otp.verify").tag("result", "invalid").tag("flow", flow).register(metrics);
            Counter.builder("gua.identity.otp.verify").tag("result", "exhausted").tag("flow", flow).register(metrics);
        }

        String provider = SmsSender.providerTag(smsSender);
        Counter.builder("gua.identity.sms.send").tag("provider", provider).tag("result", "sent").register(metrics);
        Counter.builder("gua.identity.sms.send").tag("provider", provider).tag("result", "failed").register(metrics);
    }
}
