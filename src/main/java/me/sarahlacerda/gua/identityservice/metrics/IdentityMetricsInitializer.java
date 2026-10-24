package me.sarahlacerda.gua.identityservice.metrics;

import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import me.sarahlacerda.gua.identityservice.exception.SmsRefusedException;
import me.sarahlacerda.gua.identityservice.service.SmsSendGuard;
import me.sarahlacerda.gua.identityservice.service.SmsSender;

/**
 * Eagerly registers every {@code gua_identity_*} counter family at startup, so the metric names are
 * on {@code /actuator/prometheus} from the first scrape of a fresh pod and panels read 0, not "no data":
 * <ul>
 *   <li>{@code gua_identity_signup_total{result="success",country="unknown"}}</li>
 *   <li>{@code gua_identity_login_total{result="success"}}</li>
 *   <li>{@code gua_identity_otp_verify_total{result="valid"|"invalid"|"exhausted",flow=&lt;where the code was spent&gt;}}</li>
 *   <li>{@code gua_identity_sms_send_total{provider=&lt;wired sender&gt;,result="sent"|"failed"}}</li>
 *   <li>{@code gua_identity_sms_refused_total{reason=&lt;the send limit, or the provider's reason, that refused the send&gt;}}</li>
 * </ul>
 * Registration is idempotent: {@link MeterRegistry#counter} returns the same instances for the same
 * name and tags. Only tag values the increment call sites already produce are used, so tag
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

        // Micrometer keys a meter by name: every registration of a counter must carry the same tag keys.
        for (String flow : OtpVerifyFlow.tagValues()) {
            Counter.builder("gua.identity.otp.verify").tag("result", "valid").tag("flow", flow).register(metrics);
            Counter.builder("gua.identity.otp.verify").tag("result", "invalid").tag("flow", flow).register(metrics);
            Counter.builder("gua.identity.otp.verify").tag("result", "exhausted").tag("flow", flow).register(metrics);
        }

        // provider matches whichever SmsSender bean is wired (twilio in prod, logging in dev), the same
        // value OtpService tags its increments with.
        String provider = SmsSender.providerTag(smsSender);
        Counter.builder("gua.identity.sms.send").tag("provider", provider).tag("result", "sent").register(metrics);
        Counter.builder("gua.identity.sms.send").tag("provider", provider).tag("result", "failed").register(metrics);
        // A provider refusal also counts as result="failed" above, a send limit refusal never reaches the provider.
        // The reason lives on its own meter because every gua.identity.sms.send series must keep the same tag keys.
        for (SmsRefusedException.Reason reason : SmsRefusedException.Reason.values()) {
            Counter.builder("gua.identity.sms.refused").tag("reason", reason.tagValue()).register(metrics);
        }
        for (SmsSendGuard.Refusal refusal : SmsSendGuard.Refusal.values()) {
            Counter.builder("gua.identity.sms.refused").tag("reason", refusal.tagValue()).register(metrics);
        }
    }
}
