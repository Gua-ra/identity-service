package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.twilio.Twilio;
import com.twilio.http.Request;
import com.twilio.http.Response;
import com.twilio.http.TwilioRestClient;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.filter.Filter;
import ch.qos.logback.core.read.ListAppender;
import ch.qos.logback.core.spi.FilterReply;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.exception.SmsDeliveryException;

/** A Twilio send, accepted or refused, never writes the code, the message or the whole number to any log. */
class TwilioSmsSenderTest {

    private static final String PHONE = "+16042259911";
    private static final String CODE = "482913";
    private static final String AUTH_TOKEN = "twilio-auth-token-under-test";
    private static final String TWILIO_TEXT = "The 'To' number " + PHONE + " is not a valid phone number.";

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    private final TwilioRestClient twilio = mock(TwilioRestClient.class);
    private TwilioSmsSender sender;
    private String body;

    @BeforeEach
    void setUp() {
        String testThread = Thread.currentThread().getName();
        // Spring contexts left by other test classes keep logging to the root logger from their own threads.
        logs.addFilter(new Filter<>() {
            @Override
            public FilterReply decide(ILoggingEvent event) {
                return testThread.equals(event.getThreadName()) ? FilterReply.NEUTRAL : FilterReply.DENY;
            }
        });
        logs.start();
        root.addAppender(logs);
        IdentityServiceProperties properties = new IdentityServiceProperties();
        IdentityServiceProperties.SmsProperties.TwilioProperties twilioProperties = properties.getSms().getTwilio();
        twilioProperties.setEnabled(true);
        twilioProperties.setAccountSid("ACtest");
        twilioProperties.setAuthToken(AUTH_TOKEN);
        twilioProperties.setFromNumber("+15005550006");
        sender = new TwilioSmsSender(properties);
        Twilio.setRestClient(twilio);
        when(twilio.getAccountSid()).thenReturn("ACtest");
        when(twilio.getObjectMapper()).thenReturn(new ObjectMapper());
        body = SmsTemplates.forLanguage(properties.getOtp(), "en").formatted(CODE);
    }

    @AfterEach
    void tearDown() {
        root.detachAppender(logs);
        Twilio.setRestClient(null);
        assertThat(logs.list).allSatisfy(event -> {
            assertThat(event.getFormattedMessage())
                    .doesNotContain(CODE).doesNotContain(PHONE).doesNotContain(TWILIO_TEXT).doesNotContain(AUTH_TOKEN);
            assertThat(event.getThrowableProxy()).isNull();
        });
    }

    @Test
    void anAcceptedMessageIsNotLogged() {
        when(twilio.request(any(Request.class)))
                .thenReturn(new Response("{\"sid\":\"SM00000000000000000000000000000000\",\"status\":\"queued\"}", 201));
        int before = logs.list.size();

        sender.send(PHONE, body);

        assertThat(logs.list).hasSize(before);
    }

    @Test
    void aRefusedMessageLogsAndThrowsTwiliosErrorCodeAndNeverItsText() {
        when(twilio.request(any(Request.class))).thenReturn(new Response("{\"code\":21211,\"message\":\"" + TWILIO_TEXT
                + "\",\"more_info\":\"https://www.twilio.com/docs/errors/21211\",\"status\":400}", 400));

        assertThatThrownBy(() -> sender.send(PHONE, body))
                .isInstanceOf(SmsDeliveryException.class)
                .hasMessage("Twilio refused the SMS: error 21211 (HTTP 400)")
                .hasNoCause();

        assertThat(logs.list).filteredOn(event -> event.getLevel() == Level.ERROR).singleElement()
                .satisfies(event -> assertThat(event.getFormattedMessage())
                        .isEqualTo("Failed to send SMS via Twilio to ***9911: error 21211 (HTTP 400)"));
    }
}
