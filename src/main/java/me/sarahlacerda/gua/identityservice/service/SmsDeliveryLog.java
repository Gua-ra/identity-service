package me.sarahlacerda.gua.identityservice.service;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.MeterRegistry;

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
