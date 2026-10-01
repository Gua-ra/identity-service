package me.sarahlacerda.gua.identityservice.service;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** Dev only. scripts/otp.sh greps the GUA OTP banner this logs. */
@Component
public class LoggingSmsSender implements SmsSender {

    private static final Logger log = LoggerFactory.getLogger(LoggingSmsSender.class);

    private static final Pattern CODE = Pattern.compile("\\b(\\d{4,8})\\b");

    @Override
    public void send(String e164PhoneNumber, String messageBody) {
        Matcher matcher = CODE.matcher(messageBody);
        String code = matcher.find() ? matcher.group(1) : "(see body)";
        log.info("""

                ┌──────────── GUA OTP (dev — not sent via SMS) ────────────
                │  phone : {}
                │  code  : {}
                └──────────────────────────────────────────────────────────
                """, e164PhoneNumber, code);
    }
}
