package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class SmsDeliveryLogTest {

    private static final String PHONE = "+46701740605";

    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();
    private final SmsDeliveryLog deliveryLog = new SmsDeliveryLog(new PhoneNumberMasker(), metrics);
    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(SmsDeliveryLog.class);

    @BeforeEach
    void captureLogs() {
        logs.start();
        logger.addAppender(logs);
    }

    @AfterEach
    void releaseLogs() {
        logger.detachAppender(logs);
    }

    @Test
    void aFailedSendLogsOneLogfmtLineWithTheMaskedNumber() {
        deliveryLog.record("SM42", "failed", "21408", PHONE);

        assertThat(messages()).containsExactly(
                "sms_status sid=SM42 status=failed error_code=21408 country=SE phone=+46••••0605");
        assertThat(messages().get(0)).doesNotContain("701740605");
        assertThat(metrics.counter("gua.identity.sms.delivery", "status", "failed", "error_code", "21408",
                "country", "SE").count()).isEqualTo(1.0);
    }

    @Test
    void aDeliveredSendWithoutErrorCodeLogsNone() {
        deliveryLog.record("SM42", "delivered", null, PHONE);

        assertThat(messages()).containsExactly(
                "sms_status sid=SM42 status=delivered error_code=none country=SE phone=+46••••0605");
    }

    @Test
    void aNonNumericErrorCodeIsNotATagValue() {
        deliveryLog.record("SM42", "undelivered", "30034 or-anything", PHONE);

        assertThat(metrics.counter("gua.identity.sms.delivery", "status", "undelivered", "error_code", "none",
                "country", "SE").count()).isEqualTo(1.0);
    }

    @ParameterizedTest
    @ValueSource(strings = { "queued", "accepted", "sending", "sent", "read", "canceled" })
    void aNonFinalStatusIsIgnored(String status) {
        deliveryLog.record("SM42", status, null, PHONE);

        assertThat(logs.list).isEmpty();
        assertThat(metrics.find("gua.identity.sms.delivery").counters()).isEmpty();
    }

    private List<String> messages() {
        return logs.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }
}
