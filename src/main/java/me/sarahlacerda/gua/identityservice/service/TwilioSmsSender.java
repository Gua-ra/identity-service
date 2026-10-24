package me.sarahlacerda.gua.identityservice.service;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.twilio.Twilio;
import com.twilio.exception.ApiException;
import com.twilio.exception.TwilioException;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.SmsProperties.TwilioProperties;
import me.sarahlacerda.gua.identityservice.exception.SmsRefusedException;
import me.sarahlacerda.gua.identityservice.exception.SmsUnavailableException;

/**
 * Texts through Twilio Programmable Messaging. A Twilio error that refuses the destination becomes
 * a {@link SmsRefusedException}, any other Twilio failure a {@link SmsUnavailableException}.
 */
@Component
@Primary
@ConditionalOnProperty(prefix = "identity.sms.twilio", name = "enabled", havingValue = "true")
public class TwilioSmsSender implements SmsSender {

    private static final Logger log = LoggerFactory.getLogger(TwilioSmsSender.class);

    /** Geo permission off for the region (21408), or no sender that reaches it (21606, 21612, 21659). */
    static final Set<Integer> DESTINATION_UNAVAILABLE_CODES = Set.of(21408, 21606, 21612, 21659);
    /** Not a valid number (21211), or not a mobile number (21614). */
    static final Set<Integer> INVALID_NUMBER_CODES = Set.of(21211, 21614);
    /** The recipient replied STOP to this sender. */
    static final int RECIPIENT_OPTED_OUT_CODE = 21610;

    /** Creates one message; the seam tests replace. */
    @FunctionalInterface
    interface MessageDispatcher {
        void create(PhoneNumber to, String messageBody);
    }

    private final PhoneNumberMasker masker;
    private final MessageDispatcher dispatcher;

    @Autowired
    public TwilioSmsSender(IdentityServiceProperties properties, PhoneNumberMasker masker) {
        this(masker, twilioDispatcher(properties.getSms().getTwilio(), masker));
    }

    TwilioSmsSender(PhoneNumberMasker masker, MessageDispatcher dispatcher) {
        this.masker = masker;
        this.dispatcher = dispatcher;
    }

    @Override
    public void send(String e164PhoneNumber, String messageBody) {
        try {
            dispatcher.create(new PhoneNumber(e164PhoneNumber), messageBody);
        } catch (TwilioException ex) {
            throw translate(ex, e164PhoneNumber);
        }
    }

    /**
     * Twilio's error message can quote the destination number, so only the error code, the HTTP
     * status and the masked number are logged, and the Twilio exception is not kept as a cause.
     */
    private RuntimeException translate(TwilioException ex, String e164PhoneNumber) {
        Integer code = ex instanceof ApiException api ? api.getCode() : null;
        Integer status = ex instanceof ApiException api ? api.getStatusCode() : null;
        SmsRefusedException.Reason reason = refusalReason(code);
        if (reason != null) {
            log.warn("Twilio refused SMS to {}: code={} reason={}", masker.mask(e164PhoneNumber), code,
                    reason.tagValue());
            return new SmsRefusedException(reason);
        }
        log.error("Failed to send SMS via Twilio to {}: {} code={} status={}", masker.mask(e164PhoneNumber),
                ex.getClass().getSimpleName(), code, status);
        return new SmsUnavailableException("SMS provider unavailable");
    }

    static SmsRefusedException.Reason refusalReason(Integer code) {
        if (code == null) {
            return null;
        }
        if (DESTINATION_UNAVAILABLE_CODES.contains(code)) {
            return SmsRefusedException.Reason.DESTINATION_UNAVAILABLE;
        }
        if (INVALID_NUMBER_CODES.contains(code)) {
            return SmsRefusedException.Reason.INVALID_NUMBER;
        }
        if (code == RECIPIENT_OPTED_OUT_CODE) {
            return SmsRefusedException.Reason.RECIPIENT_OPTED_OUT;
        }
        return null;
    }

    private static MessageDispatcher twilioDispatcher(TwilioProperties twilio, PhoneNumberMasker masker) {
        validateConfiguration(twilio);
        Twilio.init(twilio.getAccountSid(), twilio.getAuthToken());
        String messagingServiceSid = twilio.getMessagingServiceSid();
        // A Messaging Service (number pool, opt-out, compliance) takes precedence over a single from-number.
        if (StringUtils.hasText(messagingServiceSid)) {
            log.info("Twilio SMS sender configured using a Messaging Service");
            return (to, messageBody) -> Message.creator(to, messagingServiceSid, messageBody).create();
        }
        PhoneNumber from = new PhoneNumber(twilio.getFromNumber());
        log.info("Twilio SMS sender configured using fromNumber={}", masker.mask(twilio.getFromNumber()));
        return (to, messageBody) -> Message.creator(to, from, messageBody).create();
    }

    private static void validateConfiguration(TwilioProperties properties) {
        boolean hasSender = StringUtils.hasText(properties.getFromNumber())
            || StringUtils.hasText(properties.getMessagingServiceSid());
        if (!StringUtils.hasText(properties.getAccountSid())
            || !StringUtils.hasText(properties.getAuthToken())
            || !hasSender) {
            throw new IllegalStateException(
                "Twilio is enabled but credentials are incomplete: need accountSid, authToken, and either a fromNumber or messagingServiceSid");
        }
    }
}
