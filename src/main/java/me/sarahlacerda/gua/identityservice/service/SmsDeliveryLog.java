package me.sarahlacerda.gua.identityservice.service;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * Records the final delivery outcome Twilio reports for a message, one logfmt {@code sms_status} line
 * that joins the {@code sms_send} line by {@code sid}, and
 * {@code gua_identity_sms_delivery_total{status,error_code,country}}. A Messaging Service accepts a send
 * it later fails (21408, 21612, 30034), so this is where those refusals show up.
 */
@Component
public class SmsDeliveryLog {

    private static final Logger log = LoggerFactory.getLogger(SmsDeliveryLog.class);

    static final Set<String> FINAL_STATUSES = Set.of("delivered", "undelivered", "failed");
    static final String NO_ERROR_CODE = "none";

    private final PhoneNumberMasker masker;
    private final MeterRegistry metrics;

    public SmsDeliveryLog(PhoneNumberMasker masker, MeterRegistry metrics) {
        this.masker = masker;
        this.metrics = metrics;
    }

    /** Records {@code status} when it is final; queued, sending, sent and the like are ignored. */
    public void record(String sid, String status, String errorCode, String e164To) {
        if (status == null || !FINAL_STATUSES.contains(status)) {
            return;
        }
        String code = errorCode != null && errorCode.matches("\\d{1,6}") ? errorCode : NO_ERROR_CODE;
        String country = PhoneRegion.of(e164To);
        metrics.counter("gua.identity.sms.delivery", "status", status, "error_code", code, "country", country)
                .increment();
        log.info("sms_status sid={} status={} error_code={} country={} phone={}", sid, status, code, country,
                masker.maskWithDialCode(e164To));
    }
}
