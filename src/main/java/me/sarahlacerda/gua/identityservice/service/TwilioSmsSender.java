package me.sarahlacerda.gua.identityservice.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.twilio.Twilio;
import com.twilio.exception.ApiException;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.SmsProperties.TwilioProperties;

@Component
@Primary
@ConditionalOnProperty(prefix = "identity.sms.twilio", name = "enabled", havingValue = "true")
public class TwilioSmsSender implements SmsSender {

    private static final Logger log = LoggerFactory.getLogger(TwilioSmsSender.class);

    private final String fromNumber;
    private final String messagingServiceSid;

    public TwilioSmsSender(IdentityServiceProperties properties) {
        TwilioProperties twilio = properties.getSms().getTwilio();
        validateConfiguration(twilio);
        Twilio.init(twilio.getAccountSid(), twilio.getAuthToken());
        this.fromNumber = twilio.getFromNumber();
        this.messagingServiceSid = twilio.getMessagingServiceSid();
        log.info("Twilio SMS sender configured using {}",
            StringUtils.hasText(messagingServiceSid) ? "a Messaging Service" : "fromNumber=" + maskPhoneNumber(fromNumber));
    }

    @Override
    public void send(String e164PhoneNumber, String messageBody) {
        try {
            PhoneNumber to = new PhoneNumber(e164PhoneNumber);
            // A Messaging Service (number pool, opt-out, compliance) takes precedence over a single from-number.
            if (StringUtils.hasText(messagingServiceSid)) {
                Message.creator(to, messagingServiceSid, messageBody).create();
            } else {
                Message.creator(to, new PhoneNumber(fromNumber), messageBody).create();
            }
        } catch (ApiException ex) {
            log.error("Failed to send SMS via Twilio to {}: {}", maskPhoneNumber(e164PhoneNumber), ex.getMessage());
            throw ex;
        }
    }

    private void validateConfiguration(TwilioProperties properties) {
        boolean hasSender = StringUtils.hasText(properties.getFromNumber())
            || StringUtils.hasText(properties.getMessagingServiceSid());
        if (!StringUtils.hasText(properties.getAccountSid())
            || !StringUtils.hasText(properties.getAuthToken())
            || !hasSender) {
            throw new IllegalStateException(
                "Twilio is enabled but credentials are incomplete: need accountSid, authToken, and either a fromNumber or messagingServiceSid");
        }
    }

    private String maskPhoneNumber(String phone) {
        if (!StringUtils.hasText(phone) || phone.length() < 4) {
            return "***";
        }
        return "***" + phone.substring(phone.length() - 4);
    }
}
