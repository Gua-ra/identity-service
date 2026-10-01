package me.sarahlacerda.gua.identityservice.metrics;

import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import me.sarahlacerda.gua.identityservice.service.SmsSender;

/**
 * Eagerly registers every {@code gua_identity_*} counter family at startup, so the
 * names are present on {@code /actuator/prometheus} from a fresh pod's first scrape:
 * <ul>
 *   <li>{@code gua_identity_signup_total{result="success",country="unknown"}}</li>
 *   <li>{@code gua_identity_login_total{result="success"}}</li>
 *   <li>{@code gua_identity_otp_verify_total{result="valid"|"invalid"|"exhausted",flow=&lt;where the code was spent&gt;}}</li>
 *   <li>{@code gua_identity_sms_send_total{provider=&lt;wired sender&gt;,result="sent"|"failed"}}</li>
 * </ul>
 * Micrometer otherwise creates a counter on its first increment, so a panel built on
 * a series nothing has incremented yet reads "no data" instead of 0.
 * <p>
 * Registration is idempotent: {@link MeterRegistry#counter} returns these same
 * instances to the increment call sites for the same name and tags. Only tag values
 * those call sites already produce are registered ({@code country="unknown"} is the
 * existing fallback bucket of {@code IdentityOrchestrationService#regionOf}), so
 * cardinality is unchanged.
 */
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

        // Every verify counter carries the same two tags. Micrometer keys a meter by its name
        // alone, so a name registered with one tag set refuses a later registration carrying a
        // different one: the phone-change flow's verify counter, which adds "flow", was dropped
        // with one warning and then silently, and nothing it recorded ever reached a dashboard.
        for (String flow : OtpVerifyFlow.tagValues()) {
            Counter.builder("gua.identity.otp.verify").tag("result", "valid").tag("flow", flow).register(metrics);
            Counter.builder("gua.identity.otp.verify").tag("result", "invalid").tag("flow", flow).register(metrics);
            Counter.builder("gua.identity.otp.verify").tag("result", "exhausted").tag("flow", flow).register(metrics);
        }

        // provider matches whichever SmsSender bean is wired (twilio in prod,
        // logging in dev), the same value OtpService tags its increments with.
        String provider = SmsSender.providerTag(smsSender);
        Counter.builder("gua.identity.sms.send").tag("provider", provider).tag("result", "sent").register(metrics);
        Counter.builder("gua.identity.sms.send").tag("provider", provider).tag("result", "failed").register(metrics);
    }
}
