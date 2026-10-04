package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;

/** The dev SMS sender logs the masked number and that a code was sent, and nothing else. */
class LoggingSmsSenderTest {

    private static final String PHONE = "+16042259911";
    private static final String CODE = "482913";

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(LoggingSmsSender.class);

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
    void logsTheMaskedNumberAndNeverTheCodeOrTheMessage() {
        String body = SmsTemplates.forLanguage(new IdentityServiceProperties().getOtp(), "en").formatted(CODE);

        new LoggingSmsSender(new PhoneNumberMasker()).send(PHONE, body);

        assertThat(logs.list).singleElement().satisfies(event -> {
            assertThat(event.getFormattedMessage()).isEqualTo("Code sent to ••••9911");
            assertThat(event.getFormattedMessage()).doesNotContain(CODE).doesNotContain(PHONE);
            assertThat(event.getArgumentArray()).allSatisfy(argument -> assertThat(String.valueOf(argument))
                    .doesNotContain(CODE).doesNotContain(PHONE));
        });
    }
}
