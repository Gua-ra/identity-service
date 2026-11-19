package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import com.twilio.exception.ApiConnectionException;
import com.twilio.exception.ApiException;
import com.twilio.exception.TwilioException;
import com.twilio.type.PhoneNumber;

import me.sarahlacerda.gua.identityservice.exception.SmsRefusedException;
import me.sarahlacerda.gua.identityservice.exception.SmsRefusedException.Reason;
import me.sarahlacerda.gua.identityservice.exception.SmsUnavailableException;

class TwilioSmsSenderTest {

    private static final String PHONE = "+46701740605";
    private static final String CODE = "482913";
    private static final String BODY = "Your Gua verification code is " + CODE + ".";

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(TwilioSmsSender.class);

    @BeforeEach
    void captureLogs() {
        logs.start();
        logger.addAppender(logs);
    }

    @AfterEach
    void releaseLogs() {
        logger.detachAppender(logs);
    }

    @ParameterizedTest
    @ValueSource(ints = { 21408, 21606, 21612, 21659 })
    void aDestinationTheAccountCannotReachIsRefusedAsUnavailable(int code) {
        assertRefused(code, Reason.DESTINATION_UNAVAILABLE);
    }

    @ParameterizedTest
    @ValueSource(ints = { 21211, 21614 })
    void anInvalidOrNonMobileNumberIsRefusedAsInvalid(int code) {
        assertRefused(code, Reason.INVALID_NUMBER);
    }

    @Test
    void anOptedOutRecipientIsRefusedAsOptedOut() {
        assertRefused(21610, Reason.RECIPIENT_OPTED_OUT);
    }

    @ParameterizedTest
    @ValueSource(ints = { 20003, 20429, 21704, 30001 })
    void anyOtherApiErrorIsAnUnavailableProvider(int code) {
        TwilioSmsSender sender = failingWith(apiError(code));

        assertThatThrownBy(() -> sender.send(PHONE, BODY))
                .isExactlyInstanceOf(SmsUnavailableException.class)
                .hasNoCause();
        assertLogsKeepTheNumberCodeAndTwilioMessageOut();
    }

    @Test
    void aConnectionFailureIsAnUnavailableProvider() {
        TwilioSmsSender sender = failingWith(new ApiConnectionException("Connection Error: POST to " + PHONE));

        assertThatThrownBy(() -> sender.send(PHONE, BODY))
                .isExactlyInstanceOf(SmsUnavailableException.class)
                .hasNoCause();
        assertLogsKeepTheNumberCodeAndTwilioMessageOut();
    }

    @Test
    void anErrorWithoutACodeIsAnUnavailableProvider() {
        TwilioSmsSender sender = failingWith(new ApiException("The 'To' number " + PHONE + " failed"));

        assertThatThrownBy(() -> sender.send(PHONE, BODY)).isExactlyInstanceOf(SmsUnavailableException.class);
    }

    @Test
    void aSuccessfulSendTextsTheNumberAndLogsTheMessageSid() {
        AtomicReference<String> texted = new AtomicReference<>();
        TwilioSmsSender sender = new TwilioSmsSender(new PhoneNumberMasker(), (to, body) -> {
            texted.set(to.getEndpoint() + "|" + body);
            return "SM0123456789abcdef0123456789abcdef";
        });

        sender.send(PHONE, BODY);

        assertThat(texted.get()).isEqualTo(PHONE + "|" + BODY);
        assertThat(logs.list).singleElement().satisfies(event -> assertThat(event.getFormattedMessage())
                .isEqualTo("sms_send outcome=accepted provider=twilio sid=SM0123456789abcdef0123456789abcdef"
                        + " phone=••••0605"));
        assertLogsKeepTheNumberCodeAndTwilioMessageOut();
    }

    @Test
    void theProviderTagStaysTwilio() {
        assertThat(SmsSender.providerTag(failingWith(apiError(21408)))).isEqualTo("twilio");
    }

    private void assertRefused(int code, Reason reason) {
        TwilioSmsSender sender = failingWith(apiError(code));

        assertThatThrownBy(() -> sender.send(PHONE, BODY))
                .isInstanceOfSatisfying(SmsRefusedException.class,
                        ex -> assertThat(ex.getReason()).isEqualTo(reason))
                .hasNoCause();
        assertLogsKeepTheNumberCodeAndTwilioMessageOut();
        assertThat(logs.list).singleElement()
                .satisfies(event -> assertThat(event.getFormattedMessage()).contains("••••0605")
                        .contains("code=" + code).contains(reason.tagValue()));
    }

    private void assertLogsKeepTheNumberCodeAndTwilioMessageOut() {
        assertThat(logs.list).isNotEmpty().allSatisfy(event -> {
            assertThat(event.getFormattedMessage()).doesNotContain(PHONE).doesNotContain(CODE)
                    .doesNotContain("'To' number");
            assertThat(event.getThrowableProxy()).isNull();
        });
    }

    /** Twilio's messages quote the destination, as its API does for 21211 and 21614. */
    private static ApiException apiError(int code) {
        return new ApiException("The 'To' number " + PHONE + " is not reachable", code,
                "https://www.twilio.com/docs/errors/" + code, 400, null);
    }

    private static TwilioSmsSender failingWith(TwilioException failure) {
        return new TwilioSmsSender(new PhoneNumberMasker(), (PhoneNumber to, String body) -> {
            throw failure;
        });
    }
}
