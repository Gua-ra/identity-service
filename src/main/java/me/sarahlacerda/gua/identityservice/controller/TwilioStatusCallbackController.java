package me.sarahlacerda.gua.identityservice.controller;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.twilio.security.RequestValidator;

import io.swagger.v3.oas.annotations.Hidden;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.service.SmsDeliveryLog;

/**
 * Twilio's message status callback. The signature is checked against the configured public callback
 * URL, not the request URL, which the ingress rewrites.
 */
@Hidden
@RestController
@ConditionalOnProperty(prefix = "identity.sms.twilio", name = "enabled", havingValue = "true")
public class TwilioStatusCallbackController {

    private static final Logger log = LoggerFactory.getLogger(TwilioStatusCallbackController.class);

    static final String PATH = "/sms/twilio/status";
    static final String SIGNATURE_HEADER = "X-Twilio-Signature";

    private final String callbackUrl;
    private final RequestValidator validator;
    private final SmsDeliveryLog deliveryLog;

    public TwilioStatusCallbackController(IdentityServiceProperties properties, SmsDeliveryLog deliveryLog) {
        IdentityServiceProperties.SmsProperties.TwilioProperties twilio = properties.getSms().getTwilio();
        this.callbackUrl = twilio.getStatusCallbackUrl();
        this.validator = StringUtils.hasText(callbackUrl) && StringUtils.hasText(twilio.getAuthToken())
                ? new RequestValidator(twilio.getAuthToken())
                : null;
        this.deliveryLog = deliveryLog;
    }

    @PostMapping(path = PATH, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> status(@RequestHeader(name = SIGNATURE_HEADER, required = false) String signature,
            @RequestParam Map<String, String> params) {
        if (validator == null || !StringUtils.hasText(signature)
                || !validator.validate(callbackUrl, params, signature)) {
            log.warn("sms_status rejected reason=bad_signature");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        deliveryLog.record(params.get("MessageSid"), params.get("MessageStatus"), params.get("ErrorCode"),
                params.get("To"));
        return ResponseEntity.noContent().build();
    }
}
